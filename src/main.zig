//! This module provides a Zig interface to the uBPF virtual machine.
//! It includes functionality for creating, managing, and executing BPF programs
//! through the uBPF VM implementation.

const std = @import("std");
const validator_mod = @import("validator.zig");

/// Represents possible errors that can occur during uBPF operations
pub const UbpfError = error{
    /// Indicates failure in creating a new uBPF VM instance
    VMCreationFailed,
    /// Indicates failure in loading a BPF program into the VM
    LoadFailed,
    /// Indicates failure during BPF program execution
    ExecutionFailed,
};

/// Opaque type representing a uBPF virtual machine instance
pub const UbpfVm = opaque {};

/// Creates a new uBPF virtual machine instance
/// Returns: Optional pointer to UbpfVm, null if creation fails
pub extern fn ubpf_create() callconv(.C) ?*UbpfVm;

/// Destroys a uBPF virtual machine instance and frees associated resources
/// Parameters:
///   - vm: Pointer to the VM instance to destroy
pub extern fn ubpf_destroy(vm: ?*UbpfVm) callconv(.C) void;

/// Loads a BPF program into the virtual machine
/// Parameters:
///   - vm: Pointer to the VM instance
///   - code: Pointer to the BPF bytecode
///   - code_len: Length of the BPF bytecode
///   - errmsg: Pointer to error message buffer
/// Returns: Integer status code (0 for success)
pub extern fn ubpf_load(vm: ?*UbpfVm, code: [*]const u8, code_len: usize, errmsg: [*c][*c]u8) callconv(.C) c_int;

/// Executes the loaded BPF program
/// Parameters:
///   - vm: Pointer to the VM instance
///   - mem: Optional pointer to memory accessible by the BPF program
///   - mem_len: Length of the memory region
///   - out_ret: Pointer to store the program's return value
/// Returns: Integer status code (0 for success)
pub extern fn ubpf_exec(vm: ?*UbpfVm, mem: ?*const anyopaque, mem_len: usize, out_ret: *u64) callconv(.C) c_int;

/// Main entry point for the uBPF VM program
/// Demonstrates the complete lifecycle of creating a VM, loading and executing a BPF program
pub fn main() !void {
    std.debug.print("Debug: Program starting\n", .{});
    std.debug.print("Debug: About to create uBPF VM\n", .{});

    // Create a uBPF VM instance
    const vm = ubpf_create();
    std.debug.print("Debug: ubpf_create() returned: {?}\n", .{vm});
    if (vm == null) {
        std.debug.print("Error: Failed to create uBPF VM\n", .{});
        return UbpfError.VMCreationFailed;
    }
    defer {
        std.debug.print("Debug: Destroying VM at address: {*}\n", .{vm});
        ubpf_destroy(vm);
    }
    std.debug.print("Debug: uBPF VM created successfully at address: {*}\n", .{vm});

    // Get BPF bytecode from validator
    var validator = try validator_mod.Validator.init();
    defer validator.deinit();
    const code = try validator.validate_code();

    std.debug.print("Debug: BPF bytecode prepared, length: {}\n", .{code.len});
    std.debug.print("Debug: Code pointer: {*}, alignment: {}\n", .{ code.ptr, @alignOf(@TypeOf(code)) });

    // Allocate a buffer for the error message
    std.debug.print("Debug: Setting up error message buffer\n", .{});
    var errmsg_buf: [*c]u8 = undefined;
    const errmsg: [*c][*c]u8 = &errmsg_buf;
    std.debug.print("Debug: Error pointer of buffer at: {*}\n", .{errmsg});

    // Load the BPF program into the VM
    std.debug.print("Debug: About to load BPF program\n", .{});
    const load_result = ubpf_load(vm, code.ptr, code.len, errmsg);
    std.debug.print("Debug: ubpf_load() returned: {}\n", .{load_result});
    if (load_result != 0) {
        std.debug.print("Error: Failed to load BPF program. Error code: {}\n", .{load_result});
        if (errmsg_buf != null) {
            std.debug.print("Error message: {s}\n", .{errmsg_buf});
        }
        return UbpfError.LoadFailed;
    }
    std.debug.print("Debug: BPF program loaded successfully\n", .{});

    // Execute the BPF program
    std.debug.print("Debug: About to execute BPF program\n", .{});
    var return_value: u64 = 0;
    std.debug.print("Debug: Return value address: {*}\n", .{&return_value});
    const exec_result = ubpf_exec(vm, null, 0, &return_value);
    std.debug.print("Debug: ubpf_exec() returned: {}\n", .{exec_result});

    if (exec_result != 0) {
        std.debug.print("Error: BPF execution failed with error code: {}\n", .{exec_result});
        return UbpfError.ExecutionFailed;
    }

    std.debug.print("Success: Program executed successfully. Return value: {}\n", .{return_value});
}
