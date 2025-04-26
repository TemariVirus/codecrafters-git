const std = @import("std");
const fs = std.fs;
const AnyWriter = std.io.AnyWriter;

var gpa: std.heap.DebugAllocator(.{}) = .init;

pub fn main() !void {
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer().any();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try std.io.getStdErr().writer().print("Usage: {s} <command>\n", .{args[0]});
        return;
    }

    const command: []const u8 = args[1];
    if (strEql(command, "init")) {
        try init(stdout);
    } else if (strEql(command, "cat-file")) {
        if (args.len < 4 or !strEql(args[2], "-p")) {
            try std.io.getStdErr().writer().print("Usage: {s} cat-file -p <hash>\n", .{args[0]});
            return;
        }
        try catFile(stdout, args[3]);
    } else if (strEql(command, "hash-object")) {
        if (args.len < 3) {
            try std.io.getStdErr().writer().print("Usage: {s} hash-object [-w] <file>\n", .{args[0]});
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
    }
}

fn strEql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
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
    const allocator = gpa.allocator();

    const file = blk: {
        const path = try std.fmt.allocPrint(allocator, ".git/objects/{s}/{s}", .{ hash[0..2], hash[2..] });
        defer allocator.free(path);
        break :blk try fs.cwd().openFile(path, .{});
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
    const allocator = gpa.allocator();

    const file = try fs.cwd().openFile(file_path, .{});
    defer file.close();
    const stat = try file.stat();

    const header = try std.fmt.allocPrint(allocator, "blob {d}\x00", .{stat.size});
    defer allocator.free(header);

    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(header);
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try file.reader().readAll(&buf);
        if (n == 0) break;
        hasher.update(buf[0..n]);
    }

    const hash = std.fmt.bytesToHex(hasher.finalResult(), .lower);
    try stdout.print("{s}\n", .{hash});

    if (write) {
        const path = try std.fmt.allocPrint(allocator, ".git/objects/{s}/{s}", .{ hash[0..2], hash[2..] });
        defer allocator.free(path);
        try fs.cwd().makePath(path[0..".git/objects/00".len]);
        const obj = try fs.cwd().createFile(path, .{});
        defer obj.close();

        try file.seekTo(0);
        buf = undefined;
        var compressor = try std.compress.zlib.compressor(obj.writer(), .{});

        _ = try compressor.write(header);
        while (true) {
            const n = try file.reader().readAll(&buf);
            if (n == 0) break;
            _ = try compressor.write(buf[0..n]);
        }
        _ = try compressor.finish();
    }
}
