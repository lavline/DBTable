cmake_minimum_required(VERSION 3.11)
#set(CMAKE_C_COMPILER /usr/bin/gcc)
set(CMAKE_CXX_COMPILER /usr/local/bin/g++)
project(DBTable)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -O3 -mbmi -mbmi2")
#set(CMAKE_C_FLAGS "-O3")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

file(GLOB_RECURSE SRC_LIST "src/*.cpp" "src/*.h")
add_executable(main ${SRC_LIST})
target_link_libraries (main PUBLIC Threads::Threads)