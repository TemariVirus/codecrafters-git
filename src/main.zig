const std = @import("std");
const fs = std.fs;
const AnyReader = std.io.AnyReader;
const AnyWriter = std.io.AnyWriter;

var gpa: std.heap.DebugAllocator(.{}) = .init;
const PAGE_SIZE = 4096;

const ObjectType = enum {
    blob,
    tree,
    commit,
};

const TreeEntry = struct {
    mode: fs.File.Mode,
    name: []const u8,
    hash: [20]u8,
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

fn writeObjectHeader(writer: AnyWriter, object_type: ObjectType, file_size: u64) !void {
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
    const path = objectPath(hash);
    if (fs.cwd().access(&path, .{})) {
        // File already exists, no need to write it again
        return;
    } else |err| {
        std.mem.doNotOptimizeAway(err);
    }

    try fs.cwd().makePath(fs.path.dirname(&path).?);
    const obj = try fs.cwd().createFile(&path, .{});
    defer obj.close();

    var compressor = try std.compress.zlib.compressor(obj.writer(), .{});
    try writeObjectHeader(compressor.writer().any(), .blob, file_size);
    try compressor.compress(reader);
    try compressor.finish();
}

fn treeWriteEntriesOnly(writer: AnyWriter, entries: []const TreeEntry) !void {
    for (entries) |entry| {
        try writer.print("{d} {s}\x00{s}", .{ entry.mode, entry.name, entry.hash });
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
                    .mode = 100644,
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
                    .mode = 40000,
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

    const path = objectPath(hash);
    if (fs.cwd().access(&path, .{})) {
        // File already exists, no need to write it again
        return raw_hash;
    } else |err| {
        std.mem.doNotOptimizeAway(err);
    }

    try fs.cwd().makePath(fs.path.dirname(&path).?);
    const tree = try fs.cwd().createFile(&path, .{});
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

    var br: std.io.BufferedReader(8192, @TypeOf(file.reader())) = .{ .unbuffered_reader = file.reader() };
    var de = std.compress.zlib.decompressor(br.reader());

    try de.reader().skipUntilDelimiterOrEof('\x00');
    var buf: [8192]u8 = undefined;
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

    const file = blk: {
        const path = objectPath(hash);
        break :blk try fs.cwd().openFile(&path, .{});
    };
    defer file.close();

    var br: std.io.BufferedReader(8192, @TypeOf(file.reader())) = .{ .unbuffered_reader = file.reader() };
    var de = std.compress.zlib.decompressor(br.reader());

    {
        var tree_buf: [4]u8 = undefined;
        _ = try de.reader().readAll(&tree_buf);
        if (!strEql(&tree_buf, "tree")) {
            return error.NotATree;
        }
    }

    try de.reader().skipUntilDelimiterOrEof('\x00');
    while (true) {
        const mode = try de.reader().readUntilDelimiterOrEofAlloc(allocator, ' ', 256) orelse break;
        defer allocator.free(mode);
        const object_type: ObjectType = if (strEql(mode, "40000")) .tree else .blob;

        // There probably aren't filesystems that support 1MB filenames
        const name = try de.reader().readUntilDelimiterAlloc(allocator, '\x00', 1024 * 1024);
        defer allocator.free(name);

        var object_hash: [20]u8 = undefined;
        if (try de.reader().readAll(&object_hash) != object_hash.len) {
            return error.CorruptedFile;
        }

        if (!name_only) {
            try stdout.print("{s:0>6} {s} {}\t", .{
                mode,
                @tagName(object_type),
                std.fmt.fmtSliceHexLower(&object_hash),
            });
        }
        try stdout.print("{s}\n", .{name});
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

    const path = objectPath(hash);
    if (fs.cwd().access(&path, .{})) {
        // Commit already exists, no need to write it again
        return;
    } else |err| {
        std.mem.doNotOptimizeAway(err);
    }

    try fs.cwd().makePath(fs.path.dirname(&path).?);
    const commit = try fs.cwd().createFile(&path, .{});
    defer commit.close();

    var compressor = try std.compress.zlib.compressor(commit.writer(), .{});
    try writeObjectHeader(compressor.writer().any(), .commit, size);
    try treeCommitNoHeader(compressor.writer().any(), tree_hash, parents, message);
    try compressor.finish();
}
