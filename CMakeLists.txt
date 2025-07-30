cmake_minimum_required(VERSION 3.15)
project(AlpcMonitor C CXX)

include_directories(shared/include)

add_subdirectory(driver)
add_subdirectory(gui)