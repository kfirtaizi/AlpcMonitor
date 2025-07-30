if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

project(AlpcMonitorGUI CXX)

add_executable(AlpcMonitorGUI WIN32
    src/AlpcMonitorGUI.cpp
    src/EtwUsermodeStackCapture.cpp
    src/FilterEngine.cpp
    src/AlpcMonitorGUI.rc
)

target_compile_definitions(AlpcMonitorGUI PRIVATE UNICODE _UNICODE)

target_link_libraries(AlpcMonitorGUI PRIVATE
    comctl32
    dbghelp
    psapi
    ntdll
    tdh
    advapi32
)

message(STATUS "Configuring AlpcMonitorGUI Application")