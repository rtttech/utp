cmake_minimum_required(VERSION 3.1)

set(CMAKE_CXX_STANDARD 11)

include_directories(./)

file(
    GLOB
    SRC
    ./*.cpp
)

add_library(UTPLib ${SRC})

add_subdirectory(example)
