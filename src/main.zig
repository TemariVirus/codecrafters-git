const std = @import("std");
const fs = std.fs;
const AnyReader = std.io.AnyReader;
const AnyWriter = std.io.AnyWriter;

var gpa: std.heap.DebugAllocator(.{}) = .init;
const PAGE_SIZE = 4096;

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
        try catFile(stdout, args[3]);
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
        var hash: []const u8 = undefined;
        for (args[2..]) |arg| {
            if (strEql(arg, "--name-only")) {
                name_only = true;
            } else {
                hash = arg;
            }
        }

        try lsTree(stdout, hash, name_only);
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

fn writeBlobHeader(writer: AnyWriter, file_size: u64) !void {
    try writer.print("blob {d}\x00", .{file_size});
}

fn blobHash(reader: AnyReader, file_size: u64) ![20]u8 {
    var hasher = std.crypto.hash.Sha1.init(.{});
    writeBlobHeader(hasher.writer().any(), file_size) catch unreachable;

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
    try fs.cwd().makePath(fs.path.dirname(&path).?);
    const obj = try fs.cwd().createFile(&path, .{});
    defer obj.close();

    var compressor = try std.compress.zlib.compressor(obj.writer(), .{});
    try writeBlobHeader(compressor.writer().any(), file_size);
    try compressor.compress(reader);
    try compressor.finish();
}

fn init(stdout: AnyWriter) !void {
    const cwd = fs.cwd();
    _ = try cwd.makeDir("./.git");
    _ = try cwd.makeDir("./.git/objects");
    _ = try cwd.makeDir("./.git/refs");
    {
        const head = try cwd.createFile("./.git/HEAD", .{});
        defer head.close();
        _ = try head.write("ref: refs/heads/main\n");
    }
    _ = try stdout.writeAll("Initialized git directory\n");
}

fn catFile(stdout: AnyWriter, hash: []const u8) !void {
    const file = blk: {
        const path = objectPath(hash[0..40].*);
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

fn lsTree(stdout: AnyWriter, hash: []const u8, name_only: bool) !void {
    const allocator = gpa.allocator();

    const file = blk: {
        const path = objectPath(hash[0..40].*);
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
        const object_type = if (strEql(mode, "40000")) "tree" else "blob";

        // There probably aren't filesystems that support 1MB filenames
        const name = try de.reader().readUntilDelimiterAlloc(allocator, '\x00', 1024 * 1024);
        defer allocator.free(name);

        var object_hash: [20]u8 = undefined;
        if (try de.reader().readAll(&object_hash) != object_hash.len) {
            return error.CorruptedFile;
        }

        if (!name_only) {
            try stdout.print("{s} {s} {}\t", .{
                mode,
                object_type,
                std.fmt.fmtSliceHexLower(&object_hash),
            });
        }
        try stdout.print("{s}\n", .{name});
    }
}
