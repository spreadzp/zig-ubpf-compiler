const std = @import("std");
const main = @import("main.zig");

pub fn validated_code() ![]u8 {
    // Read the code from file
    const file = try std.fs.cwd().openFile("src/code.txt", .{});
    defer file.close();

    var buffer: [1024]u8 = undefined;
    const bytes_read = try file.readAll(&buffer);
    const content = buffer[0..bytes_read];

    // Parse the hex values from the file
    var code: [32]u8 = undefined;
    var code_index: usize = 0;

    var it = std.mem.tokenize(u8, content, " ,\n\r\t");
    while (it.next()) |token| {
        if (token[0] == '0' and token[1] == 'x' and token.len == 4) {
            const hex_str = token[2..4];
            code[code_index] = try std.fmt.parseInt(u8, hex_str, 16);
            std.debug.print("Parsed byte at index {}: 0x{x:0>2}\n", .{ code_index, code[code_index] });
            code_index += 1;
        }
    }

    std.debug.print("Total bytes parsed: {}\n", .{code_index});

    // Create VM and validate the code
    const vm = main.ubpf_create() orelse return error.VMCreationFailed;
    defer main.ubpf_destroy(vm);

    // Load and verify the program
    var errmsg: [*c][*c]u8 = undefined;
    const verified = main.ubpf_load(vm, &code, code_index, &errmsg);
    if (verified != 0) {
        if (errmsg != null) {
            std.debug.print("Error loading BPF program: {s}\n", .{errmsg[0]});
        }
        return error.InvalidBPFCode;
    }

    return &code;
}
