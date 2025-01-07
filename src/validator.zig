const std = @import("std");
const mem = std.mem;
const main = @import("main.zig");
const instructor_mod = @import("instructor.zig");

pub const ValidatorError = error{
    InfiniteLoopDetected,
    InvalidMemoryAccess,
    InvalidInstruction,
    UninitializedRegister,
    StackOverflow,
    DeadCodeDetected,
    InvalidReturnValue,
    ProgramTooLarge,
    InvalidFunctionCall,
    InvalidBPFCode,
};

const MAX_INSTRUCTIONS = 4096;

pub const Validator = struct {
    // Track visited instructions for cycle detection
    visited: std.AutoHashMap(usize, bool),
    instructor: instructor_mod.Instructor,

    pub fn init() !Validator {
        return Validator{
            .visited = std.AutoHashMap(usize, bool).init(std.heap.page_allocator),
            .instructor = instructor_mod.Instructor.init(),
        };
    }

    pub fn deinit(self: *Validator) void {
        self.visited.deinit();
    }

    pub fn validate_code(self: *Validator) ![]const u8 {
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

        // Parse and validate instructions
        var instruction_bytes: [8]u8 = undefined;
        var byte_count: usize = 0;

        var it = mem.tokenize(u8, content, " ,\n\r\t");
        std.debug.print("BPF Instructions before validation:\n", .{});

        // Count total instructions
        var instruction_count: usize = 0;

        while (it.next()) |token| {
            if (token[0] == '0' and token[1] == 'x' and token.len >= 2) {
                const hex_str = if (token.len == 4) token[2..4] else token[2..];
                if (hex_str.len > 0) {
                    instruction_bytes[byte_count] = try std.fmt.parseInt(u8, hex_str, 16);
                    byte_count += 1;

                    if (byte_count == 8) {
                        // Validate instruction before adding
                        try self.instructor.validate_instruction(&instruction_bytes);

                        @memcpy(code_struct.bytes[code_index .. code_index + 8], &instruction_bytes);
                        std.debug.print("Instruction at {}: ", .{code_index});
                        for (instruction_bytes) |b| {
                            std.debug.print("0x{x:0>2} ", .{b});
                        }
                        std.debug.print("\n", .{});

                        code_index += 8;
                        byte_count = 0;
                        instruction_count += 1;

                        if (instruction_count > MAX_INSTRUCTIONS) {
                            return error.ProgramTooLarge;
                        }
                    }
                }
            }
        }

        // Validate program structure
        try self.validate_program_structure(code_struct.bytes[0..code_index]);

        // Perform final validations using uBPF
        const vm = main.ubpf_create() orelse return error.VMCreationFailed;
        defer main.ubpf_destroy(vm);

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

    fn validate_program_structure(self: *Validator, code: []const u8) !void {
        var pc: usize = 0;
        while (pc < code.len) : (pc += 8) {
            // Check for infinite loops
            const entry = try self.visited.getOrPut(pc);
            if (entry.found_existing) {
                return error.InfiniteLoopDetected;
            }
            entry.value_ptr.* = true;

            // Analyze control flow
            const opcode = code[pc];
            if (opcode == 0x95) { // exit
                break; // Found valid exit
            }
        }

        // Check if we reached the end without finding an exit
        if (pc >= code.len) {
            return error.DeadCodeDetected;
        }
    }
};
