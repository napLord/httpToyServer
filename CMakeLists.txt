cmake_minimum_required(VERSION 2.8)

project(httpToyServer)

set(CMAKE_CXX_FLAGS  "-std=c++17 -pthread")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON )

include_directories(picohttp .)

add_subdirectory(picohttp)

add_library(threadpool threadpool.cpp)

add_executable(final server.cpp)

target_link_libraries(final picohttp threadpool)
