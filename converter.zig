const std = @import("std");
const fs = std.fs;
const mem = std.mem;

// Define the ELF header structure
const Elf64_Ehdr = extern struct {
    e_ident: [16]u8, // ELF identification
    e_type: u16, // Object file type
    e_machine: u16, // Architecture
    e_version: u32, // Object file version
    e_entry: u64, // Entry point virtual address
    e_phoff: u64, // Program header table file offset
    e_shoff: u64, // Section header table file offset
    e_flags: u32, // Processor-specific flags
    e_ehsize: u16, // ELF header size in bytes
    e_phentsize: u16, // Program header table entry size
    e_phnum: u16, // Program header table entry count
    e_shentsize: u16, // Section header table entry size
    e_shnum: u16, // Section header table entry count
    e_shstrndx: u16, // Section header string table index
};

// Define the ELF section header structure
const Elf64_Shdr = extern struct {
    sh_name: u32, // Section name (string table index)
    sh_type: u32, // Section type
    sh_flags: u64, // Section flags
    sh_addr: u64, // Section virtual address
    sh_offset: u64, // Section file offset
    sh_size: u64, // Section size in bytes
    sh_link: u32, // Link to another section
    sh_info: u32, // Additional section information
    sh_addralign: u64, // Section alignment
    sh_entsize: u64, // Entry size if section holds table
};

// Function to convert big-endian to little-endian
fn beToLe(comptime T: type, value: T) T {
    return switch (@typeInfo(T)) {
        .Int => |int| switch (int.bits) {
            16 => @byteSwap(value),
            32 => @byteSwap(value),
            64 => @byteSwap(value),
            else => value,
        },
        else => value,
    };
}

pub fn main() !void {
    // Open the object file
    const file = try fs.cwd().openFile("libprogram.a.o", .{});
    defer file.close();

    // Read the entire file into memory
    const file_size = try file.getEndPos();
    const buffer = try std.heap.page_allocator.alloc(u8, file_size);
    defer std.heap.page_allocator.free(buffer);
    _ = try file.readAll(buffer);

    // Parse the ELF header
    const elf_header = @as(*const Elf64_Ehdr, @alignCast(@ptrCast(buffer)));

    // Debug: Print ELF header fields
    std.debug.print("ELF Magic: {x}\n", .{elf_header.e_ident[0..4]});
    std.debug.print("Section Header Offset (shoff): {}\n", .{beToLe(u64, elf_header.e_shoff)});
    std.debug.print("Section Header Count (shnum): {}\n", .{beToLe(u16, elf_header.e_shnum)});
    std.debug.print("String Table Index (shstrndx): {}\n", .{beToLe(u16, elf_header.e_shstrndx)});

    // Check ELF magic number
    if (!mem.eql(u8, elf_header.e_ident[0..4], "\x7FELF")) {
        std.debug.print("Not a valid ELF file\n", .{});
        return error.InvalidElfFile;
    }

    // Validate section header offset
    const sh_off = std.math.cast(usize, beToLe(u64, elf_header.e_shoff)) orelse {
        std.debug.print("Invalid section header offset\n", .{});
        return error.InvalidSectionHeaderOffset;
    };

    if (sh_off >= buffer.len) {
        std.debug.print("Section header offset out of bounds\n", .{});
        return error.InvalidSectionHeaderOffset;
    }

    // Find the .text section
    const section_headers = @as([*]const Elf64_Shdr, @alignCast(@ptrCast(&buffer[sh_off])));

    const shstrndx = beToLe(u16, elf_header.e_shstrndx);
    const shnum = beToLe(u16, elf_header.e_shnum);

    if (shstrndx >= shnum) {
        std.debug.print("Invalid section header string table index\n", .{});
        return error.InvalidStringTableIndex;
    }

    const shdr = section_headers[shstrndx];

    // Validate string table offset
    const strtab_off = std.math.cast(usize, beToLe(u64, shdr.sh_offset)) orelse {
        std.debug.print("Invalid string table offset\n", .{});
        return error.InvalidStringTableOffset;
    };

    if (strtab_off >= buffer.len) {
        std.debug.print("String table offset out of bounds\n", .{});
        return error.InvalidStringTableOffset;
    }

    const shstrtab = buffer[strtab_off..];
    var text_offset: usize = 0;
    var text_size: usize = 0;

    for (0..shnum) |i| {
        const section_offset = sh_off + i * @sizeOf(Elf64_Shdr);
        if (section_offset >= buffer.len) {
            std.debug.print("Invalid section header offset at index {}\n", .{i});
            return error.InvalidSectionOffset;
        }

        const section = @as(*const Elf64_Shdr, @alignCast(@ptrCast(&buffer[section_offset])));

        const name_offset = std.math.cast(usize, beToLe(u32, section.sh_name)) orelse {
            continue; // Skip invalid section name
        };

        if (name_offset >= shstrtab.len) {
            continue; // Skip invalid section name
        }

        const name = std.mem.sliceTo(shstrtab[name_offset..], 0);
        std.debug.print("Section {}: {s}\n", .{ i, name });

        if (mem.eql(u8, name, ".text")) {
            text_offset = std.math.cast(usize, beToLe(u64, section.sh_offset)) orelse {
                std.debug.print("Invalid text section offset\n", .{});
                return error.InvalidTextSectionOffset;
            };
            text_size = std.math.cast(usize, beToLe(u64, section.sh_size)) orelse {
                std.debug.print("Invalid text section size\n", .{});
                return error.InvalidTextSectionSize;
            };
            break;
        }
    }

    if (text_offset == 0 or text_size == 0) {
        std.debug.print(".text section not found\n", .{});
        return error.TextSectionNotFound;
    }

    // Validate text section bounds
    if (text_offset >= buffer.len or text_offset + text_size > buffer.len) {
        std.debug.print("Invalid text section bounds\n", .{});
        return error.InvalidTextSectionBounds;
    }

    // Extract the .text section (BPF bytecode)
    const text_section = buffer[text_offset .. text_offset + text_size];

    // Format the bytecode as a sequence of hexadecimal values
    var output = std.ArrayList(u8).init(std.heap.page_allocator);
    defer output.deinit();

    for (text_section) |byte| {
        try std.fmt.format(output.writer(), "0x{x:0>2}, ", .{byte});
    }

    // Write the formatted bytecode to a text file
    const output_file = try fs.cwd().createFile("src/bpf_program.txt", .{});
    defer output_file.close();

    try output_file.writeAll(output.items);
    std.debug.print("BPF bytecode written to src/bpf_program.txt\n", .{});
}