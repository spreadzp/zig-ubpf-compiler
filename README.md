


#  setup commands
```
docker build -t ubpf-vm -f ubpf.dockerfile .
docker cp e96a3c71107f:/opt/ubpf/build/lib ./Documents/MY/ZIG/solenopsys/ubpf-vm/src
docker cp e96a3c71107f:/opt/ubpf/build/vm ./Documents/MY/ZIG/solenopsys/ubpf-vm/src
docker cp e96a3c71107f:/opt/ubpf/build/include ./Documents/MY/ZIG/solenopsys/ubpf-vm/src



zig build-exe src/main.zig -I./Documents/MY/ZIG/solenopsys/ubpf-vm/src
zig build-exe src/main.zig -I./Documents/MY/ZIG/solenopsys/ubpf-vm/src
./main

zig build-exe src/main.zig -I./src -L./src/lib -lubpf


zig run src/main.zig -Iinclude -Llib -lubpf -lc


zig build --verbose-link
zig build-exe src/main.zig -Iinclude -Llib -lubpf -lc -static

```
