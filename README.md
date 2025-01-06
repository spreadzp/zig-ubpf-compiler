# uBPF Virtual Machine in Zig

This project is a uBPF (universal Berkeley Packet Filter) virtual machine implemented in the Zig programming language. The uBPF VM is designed to execute BPF bytecode, providing a platform-independent, sandboxed, and efficient environment for network packet filtering and processing.

## Key Features

- **uBPF VM**: The core component of the project, responsible for executing BPF bytecode in a sandboxed environment, ensuring security and stability.
- **BPF Bytecode Loading**: Includes a loader for BPF bytecode, allowing users to load and execute BPF programs within the VM.
- **Error Handling**: Robust error handling mechanisms to manage and report errors during BPF code execution.

## Directory Structure

- **src**: Contains the source code for the uBPF VM and BPF bytecode loader.
- **vm**: Houses the virtual machine implementation, including the sandboxed environment.



## Prerequisites

- Docker
- Zig compiler
- Base zig_builder image

## Setup Instructions

1. Verify you have the base zig_builder image:
```bash
docker images zig_builder
```

2. Build and extract the uBPF library:
```bash
# Build the uBPF Docker image
docker build -f zig-external-libs/ubpf.dockerfile -t ubpf-builder .

# Extract the library from the container
docker create --name ubpf-temp ubpf-builder
docker cp ubpf-temp:/opt/ubpf/lib/libubpf.so ./lib/
docker rm ubpf-temp
```

Alternatively, you can run the verification script that handles the setup and verification:
```bash
chmod +x setup-lib.sh
./setup-lib.sh
```

## Running the Program

The main program demonstrates loading and executing a simple BPF program that adds two numbers:

```bash
# Run the main program
zig run src/main.zig -lc -L ./lib -lubpf -rpath $ORIGIN/lib
```

## Verifying the Library

You can verify the library setup manually with these commands:

```bash
# Check library symbols
nm -D lib/libubpf.so

# Check library dependencies
ldd lib/libubpf.so

# Check library permissions
ls -l lib/libubpf.so
```

## Example Code

The example in `src/main.zig` demonstrates:
- Creating a uBPF VM instance
- Loading a simple BPF program
- Executing the program
- Handling errors and cleanup

## Troubleshooting

If you encounter linking issues, ensure:
1. The library is properly built and extracted to the `lib` directory
2. The library has correct permissions
3. You're using the correct linking flags when running the program

For any issues, run the verify-lib.sh script to perform a complete verification of the setup.

## Usage

To use the uBPF VM, execute the `ubpf-vm` executable and provide the BPF bytecode as input. For example:

```bash

docker images zig_builder: // check if we have the base image
docker build -f zig-external-libs/ubpf.dockerfile -t ubpf-builder .   // build the uBPF image:
//  extract the library from the container:
docker create --name ubpf-temp ubpf-builder
// copy
docker cp ubpf-temp:/opt/ubpf/lib/libubpf.so ./lib/ 
// cleanup
docker rm ubpf-temp

// check
ls -l lib/libubpf.so
// run the program
env LD_PRELOAD=./lib/libubpf.so zig run src/main.zig

zig build
env LD_LIBRARY_PATH=/lib ./main

zig run src/main.zig -lc -L ./lib -lubpf -rpath $ORIGIN/lib

./zig-out/bin/ubpf-vm

nm -D lib/libubpf.so
ldd lib/libubpf.so
zig run src/main.zig -fPIC lib/libubpf.so 

ls -l lib/libubpf.so
LD_LIBRARY_PATH=./lib zig run src/main.zig -fPIC lib/libubpf.so 
env LD_DEBUG=all LD_LIBRARY_PATH=./lib zig run src/main.zig -fPIC lib/libubpf.so

```
 
This will execute the BPF bytecode within the sandboxed environment of the uBPF VM. 

##  setup commands
```
 
```

## Running the Program

```bash 
 

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