const std = @import("std");
const AnyReader = std.io.AnyReader;
const AnyWriter = std.io.AnyWriter;

const PAGE_SIZE = 4096;

pub const Type = enum {
    flush,
    delim,
    response_end,
    content,
};

pub const Pkt = union(Type) {
    flush: void,
    delim: void,
    response_end: void,
    content: []const u8,
};

pub const Iterator = struct {
    reader: AnyReader,
    buf: [65_532]u8 = undefined,

    pub fn next(self: *@This()) !?Pkt {
        const pkt_len_hex = self.reader.readBytesNoEof(4) catch |err| switch (err) {
            error.EndOfStream => return null,
            else => return err,
        };
        const pkt_len = try std.fmt.parseUnsigned(u16, &pkt_len_hex, 16);
        switch (pkt_len) {
            0 => return .flush,
            1 => return .delim,
            2 => return .response_end,
            3 => return error.PktLenTooShort,
            else => {},
        }

        const content_len: usize = pkt_len - 4;
        if (try self.reader.readAll(self.buf[0..content_len]) != content_len) {
            return error.EndOfStream;
        }
        return .{ .content = self.buf[0..content_len] };
    }
};

pub fn print(writer: AnyWriter, comptime fmt: []const u8, args: anytype) !void {
    var counter = std.io.countingWriter(std.io.null_writer);
    counter.writer().print(fmt, args) catch unreachable;
    if (counter.bytes_written > 65516) {
        return error.TooLong;
    }

    try writer.print("{x:0>4}", .{counter.bytes_written + 4});
    try writer.print(fmt, args);
}

pub fn flush(writer: AnyWriter) !void {
    try writer.writeAll("0000");
}
