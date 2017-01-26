cmake_minimum_required(VERSION 3.6)

# Project name (!= library name!)
project(acu_test)

# CMake and compiler flags
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra -pedantic")

# Add ./cmake to CMAKE_MODULE_PATH to 'source' it
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

# Link against libbroker
#
# Find the library
find_package(Broker REQUIRED)
find_package(Threads REQUIRED)



# Add the headers to include directories
include_directories(BEFORE ${BROKER_INCLUDE_DIR})
# Add the library to the LINK_LIBS
set(LINK_LIBS ${LINK_LIBS} ${BROKER_LIBRARY})

# Source files
set(SOURCE_FILES main.cpp)

# Executable definition
add_executable(acu_test ${SOURCE_FILES})
target_link_libraries(acu_test ${LINK_LIBS} pthread)