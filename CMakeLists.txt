cmake_minimum_required(VERSION 2.8)

project(httpToyServer)

SET(CMAKE_CXX_FLAGS  "-std=c++11")


include_directories(picohttp)

add_executable(final server.cpp)

add_subdirectory(picohttp)

target_link_libraries(final picohttp)
