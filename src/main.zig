const std = @import("std");

pub const UbpfError = error{
    Ok,
    InvalidInstruction,
    OutOfBounds,
    DivideByZero,
    UnsupportedCall,
    InvalidMemory,
    InvalidLength,
    InvalidString,
    InvalidMap,
    InvalidHelper,
    MaxInstructionsExceeded,
    Unknown,
};

pub const UbpfVm = opaque {};

pub const Helper = *const fn (?*UbpfVm, [*]const u64) callconv(.C) i64;

pub extern "ubpf" fn ubpf_create() ?*UbpfVm;
pub extern "ubpf" fn ubpf_destroy(vm: ?*UbpfVm) void;
pub extern "ubpf" fn ubpf_load(vm: ?*UbpfVm, code: [*]const u8, code_len: usize) c_int;
pub extern "ubpf" fn ubpf_exec(vm: ?*UbpfVm, mem: ?*const anyopaque, mem_len: usize, out_ret: *u64) c_int;
pub extern "ubpf" fn ubpf_set_error_print(vm: ?*UbpfVm, enable: bool) void;
pub extern "ubpf" fn ubpf_register(vm: ?*UbpfVm, idx: u32, fn_ptr: Helper) c_int;

pub const Vm = struct {
    vm: ?*UbpfVm,

    const Self = @This();

    pub fn init() !Self {
        std.debug.print("Creating VM...\n", .{});
        const vm = ubpf_create();
        if (vm == null) {
            std.debug.print("Failed to create VM\n", .{});
            return error.FailedToCreateVm;
        }
        std.debug.print("VM created successfully at {*}\n", .{vm});
        return Self{ .vm = vm };
    }

    pub fn deinit(self: *Self) void {
        if (self.vm) |vm| {
            std.debug.print("Destroying VM at {*}\n", .{vm});
            ubpf_destroy(vm);
            self.vm = null;
        }
    }

    pub fn load(self: *Self, code: []const u8) !void {
        std.debug.print("Loading code of length {} into VM at {*}\n", .{ code.len, self.vm });
        if (self.vm == null) return error.InvalidMemory;

        const result = ubpf_load(self.vm, code.ptr, code.len);
        std.debug.print("Load result: {}\n", .{result});
        if (result != 0) return UbpfError.InvalidInstruction;
    }

    pub fn exec(self: *Self, mem: ?[]const u8) !u64 {
        std.debug.print("Executing VM at {*}\n", .{self.vm});
        if (self.vm == null) return error.InvalidMemory;

        var out_ret: u64 = undefined;
        const result = ubpf_exec(
            self.vm,
            if (mem) |m| m.ptr else null,
            if (mem) |m| m.len else 0,
            &out_ret,
        );
        std.debug.print("Exec result: {}\n", .{result});

        if (result != 0) {
            return switch (result) {
                1 => UbpfError.InvalidInstruction,
                2 => UbpfError.OutOfBounds,
                3 => UbpfError.DivideByZero,
                4 => UbpfError.UnsupportedCall,
                5 => UbpfError.InvalidMemory,
                6 => UbpfError.InvalidLength,
                7 => UbpfError.InvalidString,
                8 => UbpfError.InvalidMap,
                9 => UbpfError.InvalidHelper,
                10 => UbpfError.MaxInstructionsExceeded,
                else => UbpfError.Unknown,
            };
        }
        return out_ret;
    }

    pub fn setErrorPrint(self: *Self, enable: bool) void {
        std.debug.print("Setting error print to {} for VM at {*}\n", .{ enable, self.vm });
        if (self.vm != null) {
            ubpf_set_error_print(self.vm, enable);
        }
    }

    pub fn registerHelper(self: *Self, idx: u32, helper: Helper) !void {
        std.debug.print("Registering helper at index {} for VM at {*}\n", .{ idx, self.vm });
        if (self.vm == null) return error.InvalidMemory;

        const result = ubpf_register(self.vm, idx, helper);
        std.debug.print("Register helper result: {}\n", .{result});
        if (result != 0) return UbpfError.InvalidHelper;
    }
};

pub fn main() !void {
    std.debug.print("Starting program\n", .{});

    var vm = try Vm.init();
    defer vm.deinit();

    std.debug.print("Enabling error printing\n", .{});
    vm.setErrorPrint(true);

    // Helper function with safe type conversion
    const printHelper = struct {
        fn helper(_: ?*UbpfVm, args: [*]const u64) callconv(.C) i64 {
            std.debug.print("Helper called with args at {*}\n", .{args});
            const value = args[0];
            std.debug.print("Helper arg value: {}\n", .{value});
            if (value > std.math.maxInt(i64)) {
                return std.math.maxInt(i64);
            }
            return @intCast(value);
        }
    };

    std.debug.print("Registering helper function\n", .{});
    try vm.registerHelper(1, &printHelper.helper);

    // Example BPF code (just a placeholder)
    const code = [_]u8{
        // mov64 r0, 1
        0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    };

    std.debug.print("Loading BPF code\n", .{});
    try vm.load(&code);

    std.debug.print("Executing BPF code\n", .{});
    const result = try vm.exec(null);
    std.debug.print("Final result: {}\n", .{result});
}
