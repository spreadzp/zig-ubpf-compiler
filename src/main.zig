const std = @import("std");
const c = @cImport({
    @cInclude("ubpf.h");
});

pub fn main() !void {
    // Create a uBPF VM instance
    const vm = c.ubpf_create();
    if (vm == null) {
        std.debug.print("Failed to create uBPF VM\n", .{});
        return error.VMCreationFailed;
    }
    std.debug.print("uBPF VM created successfully\n", .{});
    defer c.ubpf_destroy(vm);

    // Example BPF bytecode
    const code = [_]u8{
        0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov r0, 42
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    };
    std.debug.print("BPF bytecode loaded\n", .{});

    // Load the BPF program into the VM
    const load_result = c.ubpf_load(vm, @ptrCast(@constCast(&code)), code.len, null);
    if (load_result != 0) {
        std.debug.print("Failed to load BPF program. Error code: {}\n", .{load_result});
        return error.LoadFailed;
    }
    std.debug.print("BPF program loaded successfully\n", .{});

    // Variable to store the return value
    var return_value: u64 = 0;

    // Execute the BPF program
    const result = c.ubpf_exec(vm, null, 0, &return_value);

    if (result != 0) {
        std.debug.print("BPF execution failed with error code: {}\n", .{result});
        return error.ExecutionFailed;
    }

    std.debug.print("Program executed successfully. Return value: {}\n", .{return_value});
}
