const std = @import("std");

// Simple BPF program to add 10 and 32
pub fn bpf_main(ctx: *anyopaque) callconv(.C) u64 {
    _ = ctx; // Ignore context
    const a: u64 = 10;
    const b: u64 = 32;
    return a + b;
}

// Export the function
comptime {
    @export(bpf_main, .{ .name = "bpf_main" });
}

// Empty main function
pub fn main() void {}