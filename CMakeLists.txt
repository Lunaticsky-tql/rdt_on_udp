cmake_minimum_required(VERSION 3.21)
project(rdt_v1)
set(CMAKE_EXE_LINKER_FLAGS "-static")
set(CMAKE_CXX_STANDARD 14)
link_libraries(ws2_32 wsock32)


add_executable(sender sender.cpp)
add_executable(receiver receiver.cpp)