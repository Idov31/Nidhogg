cmake_minimum_required(VERSION 3.25.0)
project(NidhoggExample)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libstdc++")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++")

set(CLIENT_DIR ${CMAKE_SOURCE_DIR}/../NidhoggClient)

add_executable(NidhoggExample NidhoggExample.cpp)
target_include_directories(NidhoggExample PRIVATE ${CLIENT_DIR})

if (MSVC)
    target_compile_options(NidhoggExample PRIVATE /W4 /DUNICODE /D_UNICODE)
else()
    target_compile_options(NidhoggExample PRIVATE -Wall -Wextra -pedantic -DUNICODE -D_UNICODE)
endif()

target_link_libraries(NidhoggExample PRIVATE kernel32 user32)