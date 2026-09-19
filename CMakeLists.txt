cmake_minimum_required(VERSION 3.12)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_C_STANDARD 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(burpkat)

add_subdirectory(external/CLI11)

find_package(OpenSSL REQUIRED)

set(SOURCE_FILES
    src/main.cpp
    src/elf.cpp
    src/imports.cpp
    src/graft.cpp
    src/patch.cpp
    src/build.cpp
)

add_executable(burpkat ${SOURCE_FILES})
target_link_libraries(burpkat PRIVATE CLI11::CLI11 OpenSSL::Crypto)

project(a)
add_executable(a dummy/a.cpp)

project(b)
add_executable(b dummy/b.cpp)
set_target_properties(b PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_options(b PRIVATE -pie)
