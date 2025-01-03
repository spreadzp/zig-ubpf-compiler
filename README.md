# uBPF Virtual Machine in Zig

This project is a uBPF (universal Berkeley Packet Filter) virtual machine implemented in the Zig programming language. The uBPF VM is designed to execute BPF bytecode, providing a platform-independent, sandboxed, and efficient environment for network packet filtering and processing.

## Key Features

- **uBPF VM**: The core component of the project, responsible for executing BPF bytecode in a sandboxed environment, ensuring security and stability.
- **BPF Bytecode Loading**: Includes a loader for BPF bytecode, allowing users to load and execute BPF programs within the VM.
- **Error Handling**: Robust error handling mechanisms to manage and report errors during BPF code execution.

## Directory Structure

- **src**: Contains the source code for the uBPF VM and BPF bytecode loader.
- **vm**: Houses the virtual machine implementation, including the sandboxed environment.



## Usage

To use the uBPF VM, execute the `ubpf-vm` executable and provide the BPF bytecode as input. For example:

```bash
./zig-out/bin/ubpf-vm
```
 
This will execute the BPF bytecode within the sandboxed environment of the uBPF VM. 

##  setup commands
```
cd vm
cmake -B ../build
cd build
make  # Creates build/libubpf.a
```

## Running the Program

```bash 
 zig build  # Creates zig-out/bin/ubpf-vm
./zig-out/bin/ubpf-vm  # Runs the code in the VM

```
## Example Code
The following Zig code demonstrates a simple BPF program that adds two numbers:

```zig
  const code = [_]u8{
        0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov r0, 1
        0xb7, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov r1, 2
        0x0f, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add r0, r1
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    };

```

## Expected Result: 

After executing the code, the result should be 3.
![image](https://github.com/user-attachments/assets/7002faa9-63c6-41c9-a9d2-0c5d96888d58)

## Memory Usage
Check memory usage with the following screencast:

[Screencast from 01-03-2025 10:03:54 PM.webm](https://github.com/user-attachments/assets/43ff7cd7-077d-4a0c-b4a6-7af146d6da3e)

## Debugging Commands
 ```bash

zig build --verbose-link
zig build-exe src/main.zig -Iinclude -Llib -lubpf -lc -static

gdb ./zig-out/bin/ubpf-vm
break main
break ubpf_load
run
print vm
print code
print load_result

valgrind ./zig-out/bin/ubpf-vm
valgrind --leak-check=full ./zig-out/bin/ubpf-vm

```
## Contributing

Contributions are welcome! Please read our contributing guidelines and code of conduct before submitting pull requests.