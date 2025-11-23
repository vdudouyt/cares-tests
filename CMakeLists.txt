cmake_minimum_required(VERSION 3.10)
project(SimpleGTest)

set(CMAKE_CXX_STANDARD 11)

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

add_executable(sample_test src/main.cc)
target_link_libraries(sample_test GTest::GTest GTest::Main GTest::gmock pthread)
