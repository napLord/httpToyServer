cmake_minimum_required(VERSION 2.8)

project(httpToyServer)

set(CMAKE_CXX_FLAGS  "-std=c++17 -pthread") 

set(CMAKE_EXPORT_COMPILE_COMMANDS ON )

include_directories(picohttp .)

add_subdirectory(picohttp)

add_library(threadpool STATIC threadpool.cpp)

add_library(server STATIC server.cpp)

add_executable(main main.cpp)

target_link_libraries(main threadpool server picohttp)

