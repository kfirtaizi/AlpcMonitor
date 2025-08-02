project(ALPCMonitorDriver C)

string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")

set(WDK_ROOT "D:/Windows Kits/10")
set(WDK_VERSION "10.0.26100.0")
set(WDF_VERSION "1.33")

set(WDK_INCLUDE_PATH "${WDK_ROOT}/Include/${WDK_VERSION}/km")
set(KMDF_INCLUDE_PATH "${WDK_ROOT}/Include/wdf/kmdf/${WDF_VERSION}")
set(WDK_LIB_PATH "${WDK_ROOT}/Lib/${WDK_VERSION}/km/x64")
set(KMDF_LIB_PATH "${WDK_ROOT}/Lib/wdf/kmdf/x64/${WDF_VERSION}")

set(ZYDIS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/Zydis")
set(ZYCORE_DIR "${ZYDIS_DIR}/dependencies/zycore")

file(GLOB DRIVER_SOURCES "src/*.c")
file(GLOB ZYDIS_SOURCES "${ZYDIS_DIR}/*.c")

add_library(ALPCMonitor MODULE ${DRIVER_SOURCES} ${ZYDIS_SOURCES})

target_include_directories(ALPCMonitor PRIVATE
    "${WDK_INCLUDE_PATH}"
    "${KMDF_INCLUDE_PATH}"
    "${ZYDIS_DIR}/include"
    "${ZYCORE_DIR}/include"
    "${ZYDIS_DIR}"
)

target_compile_definitions(ALPCMonitor PRIVATE
    ZYDIS_STATIC_BUILD
    _AMD64_
)

target_compile_options(ALPCMonitor PRIVATE
    /W4
    /kernel
    /GS-
    /wd4201
)

set_target_properties(ALPCMonitor PROPERTIES
    SUFFIX ".sys"
    LINK_FLAGS "/SUBSYSTEM:NATIVE /DRIVER /ENTRY:DriverEntry /NODEFAULTLIB /MANIFEST:NO"
    LINKER_LANGUAGE "C"
)

target_link_libraries(ALPCMonitor PRIVATE
    "${WDK_LIB_PATH}/wdm.lib"
    "${KMDF_LIB_PATH}/WdfLdr.lib"
    "${KMDF_LIB_PATH}/WdfDriverEntry.lib"
    "${WDK_LIB_PATH}/ntoskrnl.lib"
)

message(STATUS "Configuring ALPCMonitor Driver")