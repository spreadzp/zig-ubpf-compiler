const std = @import("std");

pub fn build(b: *std.Build) void {
    // Get optimization options
    const optimize = b.standardOptimizeOption(.{});

    // Get target
    const target = b.standardTargetOptions(.{});

    // Create an executable
    const exe = b.addExecutable(.{
        .name = "ubpf-vm",
        .root_source_file = .{ .cwd_relative = "src/main.zig" }, // Use .path instead of .cwd_relative
        .target = target,
        .optimize = optimize,
    });

    // Link against libc
    exe.linkLibC();

    // Add include path for ubpf.h
    exe.addIncludePath(.{ .cwd_relative = "include" }); // For ubpf.h

    // Add library path for libubpf.a
    exe.addLibraryPath(.{ .cwd_relative = "build" }); // For libubpf.a

    // Link the uBPF library
    exe.linkSystemLibrary("ubpf");

    // Install the executable
    b.installArtifact(exe);

    // Create run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the application");
    run_step.dependOn(&run_cmd.step);
}
