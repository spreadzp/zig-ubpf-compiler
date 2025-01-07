const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "ubpf-vm",
        .root_source_file = .{ .cwd_relative = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    // Get current directory for absolute paths
    const cwd = std.fs.cwd();
    var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const abs_path = cwd.realpath(".", &buf) catch unreachable;

    // Add library directory to search path
    exe.addLibraryPath(.{ .cwd_relative = "lib" });

    // Add the library
    exe.linkSystemLibrary("ubpf");

    // Add rpath with absolute path to lib directory
    const rpath = b.fmt("{s}/lib", .{abs_path});
    exe.addRPath(.{ .cwd_relative = rpath });

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    // Create a run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Create a "run" step that can be invoked with `zig build run`
    const run_step = b.step("run", "Run the application");
    run_step.dependOn(&run_cmd.step);
}
