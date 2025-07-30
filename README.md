# AlpcMonitor

A utility for monitoring Advanced Local Procedure Calls (ALPC) for IPC on Windows.  

![AlpcMonitor GUI Screenshot](docs/images/alpcmonitor-gui.png)

* Can view raw RPC data ([Decrypted - No encryption is applied in the kernel even with `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`](https://learn.microsoft.com/en-us/windows/win32/rpc/authentication-level-constants#RPC_C_AUTHN_LEVEL_PKT_PRIVACY))
* Can view & filter on usermode & kernelmode callstacks of ALPC packets.
* Given an RPC SEND message (i.e. calling a remote function), can _try_ to trace the remote function's RVA & VA for easier debugging.  

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
```bash
bcdedit /set testsigning on -> Reboot
sc.exe create alpcmonitor binpath="<path-to-ALPCMonitor.sys>" type=kernel
sc.exe start alpcmonitor
```

**GUI**
* Run as admin for full set of functionalities

## Tested on
* Windows 11 24H2 (Build 26100.4652)
* Let me know if breaks on other versions!
