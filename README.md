# AlpcMonitor

A utility for monitoring Advanced Local Procedure Calls (ALPC) on Windows.

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