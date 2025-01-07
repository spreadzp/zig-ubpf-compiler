const std = @import("std");
const mem = std.mem;
const main = @import("main.zig");

pub const Validator = struct {
    pub fn init() !Validator {
        return Validator{};
    }

    pub fn validate_code(self: *const Validator) ![]const u8 {
        _ = self;
        // Read the code from file
        const file = try std.fs.cwd().openFile("src/code.txt", .{});
        defer file.close();

        var buffer: [1024]u8 = undefined;
        const bytes_read = try file.readAll(&buffer);
        const content = buffer[0..bytes_read];

        // Define the code array with proper alignment
        const Code = struct { bytes: [32]u8 align(8) = undefined };

        var code_struct = try std.heap.page_allocator.create(Code);
        var code_index: usize = 0;

        // Parse hex values in groups of 8 bytes (64-bit instructions)
        var instruction_bytes: [8]u8 = undefined;
        var byte_count: usize = 0;

        var it = mem.tokenize(u8, content, " ,\n\r\t");
        std.debug.print(" BPF Instruction before validate:   \n", .{});
        while (it.next()) |token| {
            if (token[0] == '0' and token[1] == 'x' and token.len >= 2) {
                // Skip the "0x" prefix
                const hex_str = if (token.len == 4) token[2..4] else token[2..];
                if (hex_str.len > 0) {
                    instruction_bytes[byte_count] = try std.fmt.parseInt(u8, hex_str, 16);
                    byte_count += 1;

                    // When we have 8 bytes, copy them to the code buffer
                    if (byte_count == 8) {
                        @memcpy(code_struct.bytes[code_index .. code_index + 8], &instruction_bytes);
                        std.debug.print("Instruction at {}: ", .{code_index});
                        for (instruction_bytes) |b| {
                            std.debug.print("0x{x:0>2} ", .{b});
                        }
                        std.debug.print("\n", .{});

                        code_index += 8;
                        byte_count = 0;
                    }
                }
            }
        }

        std.debug.print("Total bytes parsed: {}\n", .{code_index});

        // Create VM and validate the code
        const vm = main.ubpf_create() orelse return error.VMCreationFailed;
        defer main.ubpf_destroy(vm);

        // Load and verify the program
        var errmsg: [*c]u8 = undefined;
        const verified = main.ubpf_load(vm, &code_struct.bytes, code_index, @ptrCast(&errmsg));
        if (verified != 0) {
            if (errmsg != null) {
                std.debug.print("Error loading BPF program: {s}\n", .{errmsg});
            }
            return error.InvalidBPFCode;
        }
        return &code_struct.bytes;
    }
};
