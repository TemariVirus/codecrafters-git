const std = @import("std");
const fs = std.fs;
const AnyReader = std.io.AnyReader;
const AnyWriter = std.io.AnyWriter;

const pkt_line = @import("pkt_line.zig");

var gpa: std.heap.DebugAllocator(.{}) = .init;
const PAGE_SIZE = 4096;

const ObjectType = enum(u3) {
    invalid = 0,
    commit = 1,
    tree = 2,
    blob = 3,
    tag = 4,
    reserved = 5,
    ofs_delta = 6,
    ref_delta = 7,
};

const TreeEntry = struct {
    mode: u16,
    name: []const u8,
    hash: [20]u8,

    pub fn deinit(self: TreeEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }
};

const TreeIterator = struct {
    de: std.compress.zlib.Decompressor(fs.File.Reader),
    file: fs.File,

    pub fn init(hash: [40]u8) !TreeIterator {
        const file = blk: {
            const path = objectPath(hash);
            break :blk try fs.cwd().openFile(&path, .{});
        };
        errdefer file.close();

        var de = std.compress.zlib.decompressor(file.reader());
        {
            var tree_buf: [5]u8 = undefined;
            try de.reader().readNoEof(&tree_buf);
            if (!strEql(&tree_buf, "tree ")) {
                return error.NotATree;
            }
        }

        try de.reader().skipUntilDelimiterOrEof('\x00');
        return .{
            .de = de,
            .file = file,
        };
    }

    pub fn deinit(self: TreeIterator) void {
        self.file.close();
    }

    pub fn next(self: *TreeIterator, allocator: std.mem.Allocator) !?TreeEntry {
        const mode = blk: {
            var buf: [7]u8 = undefined;
            const str = try self.de
                .reader()
                .readUntilDelimiterOrEof(&buf, ' ') orelse return null;
            break :blk try std.fmt.parseInt(u16, str, 8);
        };

        // There probably aren't filesystems that support 1MB filenames
        const name = try self.de.reader().readUntilDelimiterAlloc(allocator, '\x00', 1024 * 1024);
        errdefer allocator.free(name);

        const hash = try self.de.reader().readBytesNoEof(20);
        return TreeEntry{
            .mode = mode,
            .name = name,
            .hash = hash,
        };
    }
};

pub fn main() !void {
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer().any();
    const stderr = std.io.getStdErr().writer().any();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try stderr.print("Usage: {s} <command>\n", .{args[0]});
        return;
    }

    const command: []const u8 = args[1];
    if (strEql(command, "init")) {
        try init(stdout);
    } else if (strEql(command, "cat-file")) {
        if (args.len < 4 or !strEql(args[2], "-p")) {
            try stderr.print("Usage: {s} cat-file -p <hash>\n", .{args[0]});
            return;
        }
        if (args[3].len != 40) {
            try stderr.print("Invalid SHA hash {s}\n", .{args[3]});
            return;
        }
        try catFile(stdout, args[3][0..40].*);
    } else if (strEql(command, "hash-object")) {
        if (args.len < 3) {
            try stderr.print("Usage: {s} hash-object [-w] <file>\n", .{args[0]});
            return;
        }

        var write = false;
        var file: []const u8 = undefined;
        for (args[2..]) |arg| {
            if (strEql(arg, "-w")) {
                write = true;
            } else {
                file = arg;
            }
        }

        try hashObject(stdout, file, write);
    } else if (strEql(command, "ls-tree")) {
        if (args.len < 3) {
            try stderr.print("Usage: {s} ls-tree [--name-only] <hash>\n", .{args[0]});
            return;
        }

        var name_only = false;
        var hash: [40]u8 = undefined;
        for (args[2..]) |arg| {
            if (strEql(arg, "--name-only")) {
                name_only = true;
            } else {
                if (arg.len != 40) {
                    try stderr.print("Invalid SHA hash: {s}\n", .{arg});
                    return;
                }
                hash = arg[0..40].*;
            }
        }

        try lsTree(stdout, hash, name_only);
    } else if (strEql(command, "write-tree")) {
        try writeTree(stdout);
    } else if (strEql(command, "commit-tree")) {
        if (args.len < 5) {
            try stderr.print("Usage: {s} commit-tree <tree_sha> [-p <commit_hash>] -m <message>\n", .{args[0]});
            return;
        }

        var tree_hash: ?[40]u8 = null;
        var parents: std.ArrayList([40]u8) = .init(allocator);
        defer parents.deinit();
        var message: ?[]const u8 = null;
        var i: usize = 2;
        while (i < args.len) {
            if (strEql(args[i], "-p")) {
                i += 1;
                if (i >= args.len) {
                    try stderr.print("Missing parent commit hash after -p\n", .{});
                    return;
                }
                if (args[i].len != 40) {
                    try stderr.print("Invalid SHA hash: {s}\n", .{args[i]});
                    return;
                }
                try parents.append(args[i][0..40].*);
            } else if (strEql(args[i], "-m")) {
                i += 1;
                if (i >= args.len) {
                    try stderr.print("Missing commit message after -m\n", .{});
                    return;
                }
                message = args[i];
            } else {
                if (args[i].len != 40) {
                    try stderr.print("Invalid SHA hash: {s}\n", .{args[i]});
                    return;
                }
                tree_hash = args[i][0..40].*;
            }
            i += 1;
        }

        if (tree_hash == null) {
            try stderr.print("Missing tree hash\n", .{});
            return;
        }
        if (message == null or message.?.len == 0) {
            try stderr.print("Missing commit message\n", .{});
            return;
        }

        try commitTree(stdout, tree_hash.?, parents.items, message.?);
    } else if (strEql(command, "checkout")) {
        if (args.len < 4 or !strEql(args[2], "-f")) {
            try stderr.print("Usage: {s} checkout -f <commit>\n", .{args[0]});
            return;
        }
        if (args[3].len != 40) {
            try stderr.print("Invalid SHA hash {s}\n", .{args[3]});
            return;
        }
        try checkout(stdout, args[3][0..40].*);
    } else if (strEql(command, "clone")) {
        if (args.len < 4) {
            try stderr.print("Usage: {s} clone <url> <path>\n", .{args[0]});
            return;
        }

        // Sanitize URL
        const uri: std.Uri = try .parse(args[2]);
        const url = try std.fmt.allocPrint(allocator, "{;@+/}", .{uri});
        defer allocator.free(url);
        try clone(stdout, stderr, std.mem.trimRight(u8, url, "/"), args[3]);
    } else {
        try stderr.print("Unknown command: {s}\n", .{command});
        return;
    }
}

fn strEql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn objectDir(hash: [40]u8) [15]u8 {
    var buf: [15]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, ".git/objects/{s}", .{hash[0..2]}) catch unreachable;
    return buf;
}

fn objectPath(hash: [40]u8) [54]u8 {
    var buf: [54]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, ".git/objects/{s}/{s}", .{ hash[0..2], hash[2..] }) catch unreachable;
    return buf;
}

fn newObject(hash: [40]u8) !?fs.File {
    const path = objectPath(hash);
    fs.cwd().access(&path, .{}) catch {
        try fs.cwd().makePath(fs.path.dirname(&path).?);
        return try fs.cwd().createFile(&path, .{});
    };
    // File already exists, no need to write it again
    return null;
}

fn readObjectAlloc(allocator: std.mem.Allocator, hash: [40]u8) !struct {
    type: ObjectType,
    bytes: []const u8,
} {
    const file = try fs.cwd().openFile(&objectPath(hash), .{});
    defer file.close();
    var de = std.compress.zlib.decompressor(file.reader());

    const obj_type = blk: {
        var buf: [7]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try de.reader().streamUntilDelimiter(fbs.writer(), ' ', fbs.buffer.len);
        break :blk std.meta.stringToEnum(ObjectType, fbs.getWritten()) orelse
            return error.InvalidObjectType;
    };

    const size = blk: {
        var buf: [21]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try de.reader().streamUntilDelimiter(fbs.writer(), '\x00', fbs.buffer.len);
        break :blk try std.fmt.parseInt(usize, fbs.getWritten(), 10);
    };
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    try de.reader().readNoEof(bytes);

    return .{ .type = obj_type, .bytes = bytes };
}

fn writeObjectHeader(writer: AnyWriter, object_type: ObjectType, file_size: u64) !void {
    switch (object_type) {
        .invalid, .tag, .reserved, .ofs_delta, .ref_delta => return error.InvalidHeaderType,
        else => {},
    }
    try writer.print("{s} {d}\x00", .{ @tagName(object_type), file_size });
}

fn blobHash(reader: AnyReader, file_size: u64) ![20]u8 {
    var hasher = std.crypto.hash.Sha1.init(.{});
    writeObjectHeader(hasher.writer().any(), .blob, file_size) catch unreachable;

    var buf: [PAGE_SIZE]u8 = undefined;
    while (true) {
        const n = try reader.readAll(&buf);
        hasher.update(buf[0..n]);
        if (n < buf.len) break;
    }
    return hasher.finalResult();
}

fn blobWrite(reader: AnyReader, file_size: u64, hash: [40]u8) !void {
    const obj = try newObject(hash) orelse return;
    defer obj.close();

    var compressor = try std.compress.zlib.compressor(obj.writer(), .{});
    try writeObjectHeader(compressor.writer().any(), .blob, file_size);
    try compressor.compress(reader);
    try compressor.finish();
}

fn treeWriteEntriesOnly(writer: AnyWriter, entries: []const TreeEntry) !void {
    for (entries) |entry| {
        try writer.print("{o} {s}\x00{s}", .{ entry.mode, entry.name, entry.hash });
    }
}

fn treeHash(entries: []const TreeEntry, size: u64) [20]u8 {
    var hasher = std.crypto.hash.Sha1.init(.{});
    writeObjectHeader(hasher.writer().any(), .tree, size) catch unreachable;
    treeWriteEntriesOnly(hasher.writer().any(), entries) catch unreachable;
    return hasher.finalResult();
}

fn treeWrite(allocator: std.mem.Allocator, dir: fs.Dir) ![20]u8 {
    const EMPTY_DIR_HASH = comptime blk: {
        var hasher = std.crypto.hash.Sha1.init(.{});
        writeObjectHeader(hasher.writer().any(), .tree, 0) catch unreachable;
        break :blk hasher.finalResult();
    };

    var entries: std.ArrayList(TreeEntry) = .init(allocator);
    defer {
        for (entries.items) |entry| {
            allocator.free(entry.name);
        }
        entries.deinit();
    }

    var it = dir.iterate();
    while (try it.next()) |entry| {
        switch (entry.kind) {
            .file => {
                const file = try dir.openFile(entry.name, .{});
                defer file.close();
                const stat = try file.stat();

                const raw_hash = try blobHash(file.reader().any(), stat.size);
                const hash = std.fmt.bytesToHex(raw_hash, .lower);
                try file.seekTo(0);
                try blobWrite(file.reader().any(), stat.size, hash);

                const name = try allocator.dupe(u8, entry.name);
                errdefer allocator.free(name);
                try entries.append(.{
                    .mode = 0o100644,
                    .name = name,
                    .hash = raw_hash,
                });
            },
            .directory => {
                // Skip all .git directories
                if (strEql(entry.name, ".git")) {
                    continue;
                }

                var subdir = try dir.openDir(entry.name, .{ .iterate = true });
                defer subdir.close();
                const raw_hash = try treeWrite(allocator, subdir);

                // Skip empty directories
                if (std.mem.eql(u8, &raw_hash, &EMPTY_DIR_HASH)) {
                    continue;
                }

                const name = try allocator.dupe(u8, entry.name);
                errdefer allocator.free(name);
                try entries.append(.{
                    .mode = 0o40000,
                    .name = name,
                    .hash = raw_hash,
                });
            },
            else => return error.UnsupportedEntryType,
        }
    }

    // Skip empty directories
    if (entries.items.len == 0) {
        return EMPTY_DIR_HASH;
    }

    std.sort.pdq(TreeEntry, entries.items, {}, (struct {
        fn lessThan(_: void, lhs: TreeEntry, rhs: TreeEntry) bool {
            return std.mem.lessThan(u8, lhs.name, rhs.name);
        }
    }).lessThan);

    const size = blk: {
        var counter = std.io.countingWriter(std.io.null_writer);
        treeWriteEntriesOnly(counter.writer().any(), entries.items) catch unreachable;
        break :blk counter.bytes_written;
    };
    const raw_hash = treeHash(entries.items, size);
    const hash = std.fmt.bytesToHex(raw_hash, .lower);

    const tree = try newObject(hash) orelse return raw_hash;
    defer tree.close();

    var compressor = try std.compress.zlib.compressor(tree.writer(), .{});
    try writeObjectHeader(compressor.writer().any(), .tree, size);
    try treeWriteEntriesOnly(compressor.writer().any(), entries.items);
    try compressor.finish();

    return raw_hash;
}

fn treeCommitNoHeader(writer: AnyWriter, tree_hash: [40]u8, parents: []const [40]u8, message: []const u8) !void {
    try writer.print("tree {s}\n", .{tree_hash});
    for (parents) |p| {
        try writer.print("parent {s}\n", .{p});
    }
    // Fixed author and committer
    // P.S. Luna was programming back in the COBOL era, I wonder if she even knows about git 🤔
    const commit_time = std.time.timestamp();
    try writer.print("author Himemori Luna <himemori.luna@nnaaaa.com> {d} +0000\n", .{commit_time});
    try writer.print("committer Himemori Luna <himemori.luna@nnaaaa.com> {d} +0000\n", .{commit_time});
    try writer.print("\n{s}\n", .{message});
}

// Assumes --force
fn checkoutTree(allocator: std.mem.Allocator, hash: [40]u8, dir: fs.Dir) !void {
    var it: TreeIterator = try .init(hash);
    defer it.deinit();
    while (try it.next(allocator)) |entry| {
        defer entry.deinit(allocator);

        const obj_type: ObjectType = if (entry.mode == 0o40000) .tree else .blob;
        const obj_hash = std.fmt.bytesToHex(entry.hash, .lower);
        switch (obj_type) {
            .blob => {
                const file = try dir.createFile(entry.name, .{});
                defer file.close();

                const blob = try fs.cwd().openFile(&objectPath(obj_hash), .{});
                defer blob.close();

                var de = std.compress.zlib.decompressor(blob.reader());
                try de.reader().skipUntilDelimiterOrEof('\x00');
                try de.decompress(file.writer());
            },
            .tree => {
                try dir.makeDir(entry.name);
                var subdir = try dir.openDir(entry.name, .{});
                defer subdir.close();
                try checkoutTree(allocator, obj_hash, subdir);
            },
            else => unreachable,
        }
    }
}

fn packfileReadSize(reader: AnyReader) !u64 {
    var offset: u6 = 0;
    var size: u64 = 0;
    while (true) : (offset += 7) {
        const byte = try reader.readByte();
        size |= @as(u64, byte & 0x7f) << offset;
        if ((byte >> 7) & 0x1 == 0) {
            return size;
        }
    }
}

fn deltaReadCopy(delta: AnyReader, set: u7) !struct { offset: u32, size: u24 } {
    var offset_bytes: [4]u8 = @splat(0);
    for (0..offset_bytes.len) |i| {
        if ((set >> @intCast(i)) & 1 == 1) {
            offset_bytes[i] = try delta.readByte();
        }
    }

    var size_bytes: [3]u8 = @splat(0);
    for (0..size_bytes.len) |i| {
        if ((set >> @intCast(offset_bytes.len + i)) & 1 == 1) {
            size_bytes[i] = try delta.readByte();
        }
    }

    const size = std.mem.readInt(u24, &size_bytes, .little);
    return .{
        .offset = std.mem.readInt(u32, &offset_bytes, .little),
        .size = if (size == 0) 0x10000 else size,
    };
}

fn unDeltatify(base_obj: *std.io.StreamSource, obj_type: ObjectType, delta: AnyReader, writer: AnyWriter) !void {
    _ = try packfileReadSize(delta); // Size of base object
    {
        const output_size = try packfileReadSize(delta);
        try writeObjectHeader(writer, obj_type, output_size);
    }

    while (true) {
        const byte = delta.readByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        switch (byte) {
            // Reserved instruction
            0x00 => continue,
            // Add instruction
            0x01...0x7f => {
                const data_len = byte & 0x7f;
                var buf: [0x7f]u8 = undefined;
                try delta.readNoEof(buf[0..data_len]);
                try writer.writeAll(buf[0..data_len]);
            },
            // Copy instruction
            0x80...0xff => {
                const instruction = try deltaReadCopy(delta, @truncate(byte));
                try base_obj.seekTo(instruction.offset);

                var remaining_len = instruction.size;
                var buf: [PAGE_SIZE]u8 = undefined;
                while (remaining_len > 0) {
                    const len = @min(remaining_len, buf.len);
                    try base_obj.reader().readNoEof(buf[0..len]);
                    try writer.writeAll(buf[0..len]);
                    remaining_len -= @intCast(len);
                }
            },
        }
    }
}

fn init(stdout: AnyWriter) !void {
    const cwd = fs.cwd();
    try cwd.makePath("./.git/objects");
    try cwd.makePath("./.git/refs");
    {
        const head = try cwd.createFile("./.git/HEAD", .{});
        defer head.close();
        _ = try head.write("ref: refs/heads/main\n");
    }
    _ = try stdout.writeAll("Initialized git directory\n");
}

fn catFile(stdout: AnyWriter, hash: [40]u8) !void {
    const file = blk: {
        const path = objectPath(hash);
        break :blk try fs.cwd().openFile(&path, .{});
    };
    defer file.close();

    var de = std.compress.zlib.decompressor(file.reader());
    try de.reader().skipUntilDelimiterOrEof('\x00');

    var buf: [PAGE_SIZE]u8 = undefined;
    while (true) {
        const n = try de.reader().readAll(&buf);
        if (n == 0) break;
        try stdout.writeAll(buf[0..n]);
    }
}

fn hashObject(stdout: AnyWriter, file_path: []const u8, write: bool) !void {
    const file = try fs.cwd().openFile(file_path, .{});
    defer file.close();
    const stat = try file.stat();

    const raw_hash = try blobHash(file.reader().any(), stat.size);
    const hash = std.fmt.bytesToHex(raw_hash, .lower);
    try stdout.print("{s}\n", .{hash});

    if (write) {
        try file.seekTo(0);
        try blobWrite(file.reader().any(), stat.size, hash);
    }
}

fn lsTree(stdout: AnyWriter, hash: [40]u8, name_only: bool) !void {
    const allocator = gpa.allocator();

    var it: TreeIterator = try .init(hash);
    defer it.deinit();
    while (try it.next(allocator)) |entry| {
        defer entry.deinit(allocator);

        const object_type: ObjectType = if (entry.mode == 0o40000) .tree else .blob;
        if (!name_only) {
            try stdout.print("{o:0>6} {s} {}\t", .{
                entry.mode,
                @tagName(object_type),
                std.fmt.fmtSliceHexLower(&entry.hash),
            });
        }
        try stdout.print("{s}\n", .{entry.name});
    }
}

fn writeTree(stdout: AnyWriter) !void {
    const allocator = gpa.allocator();

    var cwd = try fs.cwd().openDir(".", .{ .iterate = true });
    defer cwd.close();
    const raw_hash = try treeWrite(allocator, cwd);
    try stdout.print("{}\n", .{std.fmt.fmtSliceHexLower(&raw_hash)});
}

fn commitTree(stdout: AnyWriter, tree_hash: [40]u8, parents: []const [40]u8, message: []const u8) !void {
    const size = blk: {
        var counter = std.io.countingWriter(std.io.null_writer);
        treeCommitNoHeader(counter.writer().any(), tree_hash, parents, message) catch unreachable;
        break :blk counter.bytes_written;
    };

    const raw_hash = blk: {
        var hasher = std.crypto.hash.Sha1.init(.{});
        writeObjectHeader(hasher.writer().any(), .commit, size) catch unreachable;
        treeCommitNoHeader(hasher.writer().any(), tree_hash, parents, message) catch unreachable;
        break :blk hasher.finalResult();
    };
    const hash = std.fmt.bytesToHex(raw_hash, .lower);

    try stdout.print("{s}\n", .{hash});

    const commit = try newObject(hash) orelse return;
    defer commit.close();

    var compressor = try std.compress.zlib.compressor(commit.writer(), .{});
    try writeObjectHeader(compressor.writer().any(), .commit, size);
    try treeCommitNoHeader(compressor.writer().any(), tree_hash, parents, message);
    try compressor.finish();
}

// Assumes --force
fn checkout(stdout: AnyWriter, hash: [40]u8) !void {
    const allocator = gpa.allocator();

    {
        const head = try fs.cwd().createFile(".git/HEAD", .{});
        defer head.close();
        try head.writeAll(&hash);
    }

    const tree_hash = blk: {
        const commit = try readObjectAlloc(allocator, hash);
        defer allocator.free(commit.bytes);
        if (commit.type != .commit) {
            return error.NotACommit;
        }
        break :blk commit.bytes[5..45].*;
    };
    try checkoutTree(allocator, tree_hash, fs.cwd());

    try stdout.print("HEAD is now at {s}\n", .{&hash});
}

fn clone(stdout: AnyWriter, stderr: AnyWriter, url: []const u8, path: []const u8) !void {
    const allocator = gpa.allocator();

    {
        var dir = try fs.cwd().makeOpenPath(path, .{ .iterate = true });
        defer dir.close();
        try dir.setAsCwd();

        var it = dir.iterate();
        while (try it.next()) |_| {
            return try stderr.print(
                "fatal: destination path '{s}' already exists and is not an empty directory.",
                .{path},
            );
        }
    }
    try stdout.print("Cloning into '{s}'...\n", .{path});
    try init(std.io.null_writer.any());

    var http: std.http.Client = .{ .allocator = allocator };
    defer http.deinit();
    const path_buf = try allocator.alloc(u8, url.len + 34);
    defer allocator.free(path_buf);

    const head_hash = get_head: {
        const location = std.fmt.bufPrint(path_buf, "{s}/info/refs?service=git-upload-pack", .{url}) catch unreachable;

        var server_header_buffer: [16 * 1024]u8 = undefined;
        var req = try http.open(
            .GET,
            try std.Uri.parse(location),
            .{
                .extra_headers = &.{.{ .name = "git-protocol", .value = "version=0" }},
                .server_header_buffer = &server_header_buffer,
            },
        );
        defer req.deinit();

        try req.send();
        try req.wait();
        if (req.response.status != .ok and req.response.status != .not_modified) {
            return error.HttpRequestFailed;
        }

        var pkts: pkt_line.Iterator = .{ .reader = req.reader().any() };
        _ = try pkts.next(); // # service=git-upload-pack\x0a
        _ = try pkts.next(); // flush
        while (try pkts.next()) |pkt| {
            switch (pkt) {
                .content => |data| {
                    const content = std.mem.trimRight(u8, data, "\n");
                    const ref_len = std.mem.indexOfScalar(u8, content, '\x00') orelse content.len;

                    var ref_parts = std.mem.splitScalar(u8, content[0..ref_len], ' ');
                    const hash = blk: {
                        const part = ref_parts.first();
                        if (part.len != 40) {
                            return error.InvalidRef;
                        }
                        break :blk part[0..40].*;
                    };
                    const name = ref_parts.next() orelse return error.InvalidRef;
                    if (std.mem.eql(u8, name, "HEAD")) {
                        break :get_head hash;
                    }
                },
                else => {},
            }
        }
        return error.NoHeadRef;
    };

    const packfile_bytes: []const u8 = packfile: {
        const location = std.fmt.bufPrint(path_buf, "{s}/git-upload-pack", .{url}) catch unreachable;

        var server_header_buffer: [16 * 1024]u8 = undefined;
        var req = try http.open(
            .POST,
            try std.Uri.parse(location),
            .{
                .headers = .{ .content_type = .{ .override = "application/x-git-upload-pack-request" } },
                .extra_headers = &.{.{ .name = "git-protocol", .value = "version=0" }},
                .server_header_buffer = &server_header_buffer,
            },
        );
        defer req.deinit();

        req.transfer_encoding = .chunked;
        try req.send();
        // We only want HEAD and have no objects
        try pkt_line.print(req.writer().any(), "want {s} side-band-64k\n", .{head_hash});
        try pkt_line.flush(req.writer().any());
        try pkt_line.print(req.writer().any(), "done\n", .{});
        try req.finish();
        try req.wait();

        if (req.response.status != .ok) {
            return error.HttpRequestFailed;
        }

        var btyes: std.ArrayList(u8) = .init(allocator);
        defer btyes.deinit();
        var pkts: pkt_line.Iterator = .{ .reader = req.reader().any() };
        _ = try pkts.next(); // NAK\x0a
        while (try pkts.next()) |pkt| {
            switch (pkt) {
                .content => |data| {
                    const sideband = data[0];
                    const content = data[1..];
                    switch (sideband) {
                        1 => try btyes.appendSlice(content),
                        2 => try stdout.print("remote: {s}", .{content}),
                        3 => try stderr.print("remote: {s}", .{content}),
                        else => return error.InvalidSideband,
                    }
                },
                else => {},
            }
        }
        break :packfile try btyes.toOwnedSlice();
    };
    defer allocator.free(packfile_bytes);

    var packfile_stream = std.io.fixedBufferStream(packfile_bytes);
    const packfile = packfile_stream.reader();
    try packfile.skipBytes(8, .{}); // Skip signature and version
    const obj_count = try packfile.readInt(u32, .big);
    for (0..obj_count) |_| {
        const obj_type, const obj_len = blk: {
            const byte = try packfile.readByte();
            const obj_type: ObjectType = @enumFromInt((byte >> 4) & 0x07);
            const obj_len: u64 = byte & 0x0f;
            const obj_len_remaining = if ((byte >> 7) & 0x1 == 1) try packfileReadSize(packfile.any()) else 0;
            break :blk .{ obj_type, obj_len | (obj_len_remaining << 4) };
        };

        switch (obj_type) {
            .commit, .tree, .blob => {
                const start_pos = packfile_stream.pos;
                const hash = blk: {
                    var hasher = std.crypto.hash.Sha1.init(.{});
                    writeObjectHeader(hasher.writer().any(), obj_type, obj_len) catch unreachable;
                    try std.compress.zlib.decompress(packfile, hasher.writer());
                    const raw_hash: [20]u8 = hasher.finalResult();
                    break :blk std.fmt.bytesToHex(raw_hash, .lower);
                };

                packfile_stream.seekTo(@intCast(start_pos)) catch unreachable;
                const obj = try newObject(hash) orelse {
                    try std.compress.zlib.decompress(packfile, std.io.null_writer);
                    continue;
                };
                defer obj.close();

                var compressor = try std.compress.zlib.compressor(obj.writer(), .{});
                try writeObjectHeader(compressor.writer().any(), obj_type, obj_len);
                try std.compress.zlib.decompress(packfile, compressor.writer());
                try compressor.finish();
            },
            .ref_delta => {
                const ref_hash = std.fmt.bytesToHex(try packfile.readBytesNoEof(20), .lower);

                const delta = blk: {
                    const buf = try allocator.alloc(u8, obj_len);
                    errdefer allocator.free(buf);
                    var fbs = std.io.fixedBufferStream(buf);
                    try std.compress.zlib.decompress(packfile, fbs.writer());
                    break :blk buf;
                };
                defer allocator.free(delta);
                var delta_stream = std.io.fixedBufferStream(delta);

                const base_obj = try readObjectAlloc(allocator, ref_hash);
                defer allocator.free(base_obj.bytes);
                var base_stream: std.io.StreamSource = .{ .const_buffer = std.io.fixedBufferStream(base_obj.bytes) };

                const hash = blk: {
                    delta_stream.reset();
                    var hasher = std.crypto.hash.Sha1.init(.{});
                    try unDeltatify(&base_stream, base_obj.type, delta_stream.reader().any(), hasher.writer().any());
                    break :blk std.fmt.bytesToHex(hasher.finalResult(), .lower);
                };

                delta_stream.reset();
                const obj = try newObject(hash) orelse continue;
                defer obj.close();
                var compressor = try std.compress.zlib.compressor(obj.writer(), .{});
                try unDeltatify(&base_stream, base_obj.type, delta_stream.reader().any(), compressor.writer().any());
                try compressor.finish();
            },
            .invalid, .tag, .reserved, .ofs_delta => return error.UnsupportedObject,
        }
    }

    // Check checksum
    {
        var computed_hash: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
        std.crypto.hash.Sha1.hash(packfile_stream.buffer[0..packfile_stream.pos], &computed_hash, .{});
        const received_hash = packfile_stream.buffer[packfile_stream.pos..];
        if (!std.mem.eql(u8, received_hash, &computed_hash)) {
            return error.CorruptedPackfile;
        }
    }

    try checkout(std.io.null_writer.any(), head_hash);
}
