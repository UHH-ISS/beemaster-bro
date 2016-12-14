cmake_minimum_required(VERSION 3.6)
project(broker_test)

# Add some default cxx flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra -pedantic")

# Some common broker paths bound for convenience
set(BROKER_DIR /usr/local/bro)
set(BROKER_INCLUDE_DIR ${BROKER_DIR}/include)
set(BROKER_LIB_DIR ${BROKER_DIR}/lib)

# Add broker to include directories so headers are found
include_directories(${BROKER_INCLUDE_DIR})

# Find broker shared library (libbroker.so) to use later in linking phase
# Apparently this is the preferred way of doing this although `link_directories($BROKER_LIB_DIR}) also works..
find_library(BROKER broker ${BROKER_LIB_DIR})

# Explicitly list our used broker headers (not sure if this is required but it is recommended a lot)
set(BROKER_HEADERS
        ${BROKER_INCLUDE_DIR}/broker/broker.hh
        ${BROKER_INCLUDE_DIR}/broker/endpoint.hh
        ${BROKER_INCLUDE_DIR}/broker/message_queue.hh)

# Set our source files
set(SOURCE_FILES main.cpp)

# Define an executable..
add_executable(broker_test ${SOURCE_FILES} ${BROKER_HEADERS})
# ..and the required libraries during linking
target_link_libraries(broker_test ${BROKER})
