const std = @import("std");
const ValidatorError = error{
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

const MAX_STACK_SIZE = 512;

pub const Instructor = struct {
    // Track register initialization state
    reg_state: [11]bool, // r0-r10
    // Track current stack usage
    stack_size: usize,

    pub fn init() Instructor {
        return Instructor{
            .reg_state = [_]bool{false} ** 11,
            .stack_size = 0,
        };
    }

    pub fn validate_instruction(self: *Instructor, instruction: *const [8]u8) !void {
        const opcode = instruction[0];
        const dst_reg = instruction[1] & 0xf;
        const src_reg = (instruction[1] >> 4) & 0xf;

        // Check register bounds first for all instructions
        if (dst_reg > 10 or src_reg > 10) {
            return error.InvalidInstruction;
        }

        // Check for valid opcode
        switch (opcode) {
            // ALU instructions (64-bit)
            0x07 => { // add imm
                if (!self.reg_state[dst_reg]) return error.UninitializedRegister;
                self.reg_state[dst_reg] = true;
            },
            0x0f => { // add reg
                if (!self.reg_state[dst_reg] or !self.reg_state[src_reg]) {
                    return error.UninitializedRegister;
                }
            },
            0x17 => { // sub imm
                if (!self.reg_state[dst_reg]) return error.UninitializedRegister;
                self.reg_state[dst_reg] = true;
            },
            0x1f => { // sub reg
                if (!self.reg_state[dst_reg] or !self.reg_state[src_reg]) {
                    return error.UninitializedRegister;
                }
            },
            0x27 => { // mul imm
                if (!self.reg_state[dst_reg]) return error.UninitializedRegister;
                self.reg_state[dst_reg] = true;
            },
            0x2f => { // mul reg
                if (!self.reg_state[dst_reg] or !self.reg_state[src_reg]) {
                    return error.UninitializedRegister;
                }
            },
            0x37 => { // div imm
                if (!self.reg_state[dst_reg]) return error.UninitializedRegister;
                if (instruction[4] == 0) return error.InvalidInstruction; // Prevent division by zero
                self.reg_state[dst_reg] = true;
            },
            0x3f => { // div reg
                if (!self.reg_state[dst_reg] or !self.reg_state[src_reg]) {
                    return error.UninitializedRegister;
                }
            },
            0x47 => { // or imm
                if (!self.reg_state[dst_reg]) return error.UninitializedRegister;
                self.reg_state[dst_reg] = true;
            },
            0x4f => { // or reg
                if (!self.reg_state[dst_reg] or !self.reg_state[src_reg]) {
                    return error.UninitializedRegister;
                }
            },
            0x57 => { // and imm
                if (!self.reg_state[dst_reg]) return error.UninitializedRegister;
                self.reg_state[dst_reg] = true;
            },
            0x5f => { // and reg
                if (!self.reg_state[dst_reg] or !self.reg_state[src_reg]) {
                    return error.UninitializedRegister;
                }
            },
            0x67 => { // lsh imm
                if (!self.reg_state[dst_reg]) return error.UninitializedRegister;
                self.reg_state[dst_reg] = true;
            },
            0x6f => { // lsh reg
                if (!self.reg_state[dst_reg] or !self.reg_state[src_reg]) {
                    return error.UninitializedRegister;
                }
            },
            0x77 => { // rsh imm
                if (!self.reg_state[dst_reg]) return error.UninitializedRegister;
                self.reg_state[dst_reg] = true;
            },
            0x7f => { // rsh reg
                if (!self.reg_state[dst_reg] or !self.reg_state[src_reg]) {
                    return error.UninitializedRegister;
                }
            },

            // Memory operations
            0x61 => { // ldxw: load word
                if (!self.reg_state[src_reg]) return error.UninitializedRegister;
                self.reg_state[dst_reg] = true;
                try self.validate_memory_access(instruction);
            },
            0x69 => { // ldxh: load half word
                if (!self.reg_state[src_reg]) return error.UninitializedRegister;
                self.reg_state[dst_reg] = true;
                try self.validate_memory_access(instruction);
            },
            0x71 => { // ldxb: load byte
                if (!self.reg_state[src_reg]) return error.UninitializedRegister;
                self.reg_state[dst_reg] = true;
                try self.validate_memory_access(instruction);
            },
            0x79 => { // ldxdw: load double word
                if (!self.reg_state[src_reg]) return error.UninitializedRegister;
                self.reg_state[dst_reg] = true;
                try self.validate_memory_access(instruction);
            },

            // Immediate loads
            0xb7 => { // mov imm
                self.reg_state[dst_reg] = true;
            },
            0xbf => { // mov reg
                if (!self.reg_state[src_reg]) return error.UninitializedRegister;
                self.reg_state[dst_reg] = true;
            },

            // Jump instructions
            0x05 => { // ja: jump always
                // No register validation needed for unconditional jump
            },
            0x15 => { // jeq imm: jump if equal
                if (!self.reg_state[dst_reg]) return error.UninitializedRegister;
            },
            0x1d => { // jeq reg: jump if equal
                if (!self.reg_state[dst_reg] or !self.reg_state[src_reg]) {
                    return error.UninitializedRegister;
                }
            },
            0x25 => { // jgt imm: jump if greater than
                if (!self.reg_state[dst_reg]) return error.UninitializedRegister;
            },
            0x2d => { // jgt reg: jump if greater than
                if (!self.reg_state[dst_reg] or !self.reg_state[src_reg]) {
                    return error.UninitializedRegister;
                }
            },
            0x35 => { // jge imm: jump if greater or equal
                if (!self.reg_state[dst_reg]) return error.UninitializedRegister;
            },
            0x3d => { // jge reg: jump if greater or equal
                if (!self.reg_state[dst_reg] or !self.reg_state[src_reg]) {
                    return error.UninitializedRegister;
                }
            },

            // Program exit
            0x95 => { // exit
                if (!self.reg_state[0]) { // r0 must be initialized for return
                    return error.InvalidReturnValue;
                }
            },

            else => return error.InvalidInstruction,
        }

        // Track stack operations
        if (self.is_stack_operation(opcode)) {
            const offset = @as(u8, @bitCast(instruction[4]));
            if (offset > MAX_STACK_SIZE) {
                return error.StackOverflow;
            }
            self.stack_size = @max(self.stack_size, @as(usize, offset));
        }
    }

    fn validate_memory_access(self: *Instructor, instruction: *const [8]u8) !void {
        _ = self;
        const offset = @as(i32, @bitCast(@as(u32, instruction[4]) |
            @as(u32, instruction[5]) << 8 |
            @as(u32, instruction[6]) << 16 |
            @as(u32, instruction[7]) << 24));

        if (offset < 0 or offset > MAX_STACK_SIZE) {
            return error.InvalidMemoryAccess;
        }
    }

    fn is_stack_operation(self: *Instructor, opcode: u8) bool {
        _ = self;
        return opcode == 0x63 or opcode == 0x7b; // Example stack operation opcodes
    }
};
