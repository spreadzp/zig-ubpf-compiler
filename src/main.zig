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
    std.debug.print("uBPF VM created successfully at address: {*}\n", .{vm});
    defer c.ubpf_destroy(vm);

    // Cast the VM pointer to a byte pointer for logging
    const vm_ptr: [*]const u8 = @ptrCast(vm);
    std.debug.print("VM pointer: {*}\n", .{vm_ptr});

    // Example BPF bytecode
    const code = [_]u8{
        0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov r0, 1
        0xb7, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov r1, 2
        0x0f, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add r0, r1
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    };
    std.debug.print("BPF bytecode loaded\n", .{});

    // Load the BPF program into the VM
    const code_ptr: [*]const u8 = @ptrCast(&code[0]);
    const code_len = code.len;

    // Log the code pointer address and length
    std.debug.print("Code pointer: {*}, Code length: {}\n", .{ code_ptr, code_len });

    if (code_len == 0) {
        std.debug.print("Invalid bytecode length\n", .{});
        return error.InvalidArgument;
    }

    // Debug: Print the first few bytes of the bytecode
    std.debug.print("Bytecode (first 8 bytes): {x}\n", .{code[0..8]});

    // Allocate a buffer for the error message
    var errmsg_buf: [*c]u8 = undefined; // Pointer to a null-terminated string
    const errmsg: [*c][*c]u8 = &errmsg_buf; // Pointer to the pointer

    // Call ubpf_load with the error message buffer
    const load_result = c.ubpf_load(vm, code_ptr, code_len, errmsg);
    if (load_result != 0) {
        // Print the error message if the load failed
        std.debug.print("Failed to load BPF program. Error: {s}\n", .{errmsg_buf});
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
