# AlpcMonitor

A utility for monitoring Advanced Local Procedure Calls (ALPC) on Windows.
![AlpcMonitor GUI Screenshot](docs/images/alpcmonitor-gui.png)

* Can view usermode & kernelmode callstacks.
* Given an RPC SEND message (i.e. calling a remote function), can _try_ to trace the remote function's RVA for easier debugging.
![Callstack and RPC Callee](docs/images/callstack-and-rpc-callee.png)

## Build Instructions

**1. Clone the repository:**
```bash
git clone https://github.com/kfirtaizi/AlpcMonitor
cd AlpcMonitor
```

**2. Create build files with CMake:**
```bash
mkdir build && cd build
cmake -A x64 ..
```

**3. Compile the code:**
```bash
# Build for Debug
cmake --build . --config Debug

# Or build for Release
cmake --build . --config Release
```

**Binaries are located in:**
* `build/gui/Debug/`
* `build/driver/Debug/`

## Install Instructions

**Driver**
* `bcdedit /set testsigning on` -> Reboot
* `sc.exe create alpcmonitor binpath="C:\Users\asdsa\Desktop\ALPCMonitor.sys" type=kernel`
* `sc.exe start alpcmonitor`

**GUI**
* Run as admin for full functionalities