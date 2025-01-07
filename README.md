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

zig build-exe src/main.zig -lc -L ./lib -lubpf -rpath $ORIGIN/lib -fno-strip
lldb ./main
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
 

After executing the code, the result should be 3.
![Screenshot from 2025-01-06 16-04-23](https://github.com/user-attachments/assets/83cd3fbc-c714-402a-b890-f6670056449e)


 
## Contributing

Contributions are welcome! Please read our contributing guidelines and code of conduct before submitting pull requests.