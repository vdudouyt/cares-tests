cmake_minimum_required(VERSION 3.10)
project(SimpleGTest)

set(CMAKE_CXX_STANDARD 11)

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

add_executable(sample_test src/main.cc src/impl.c src/dns-proto.cc src/ares-test.cc src/ares-test-parse-a.cc src/ares-test-parse-aaaa.cc)
target_link_libraries(sample_test GTest::GTest GTest::Main GTest::gmock pthread
   #/home/vdudouyt/git/cares-rs/target/debug/libcares_rs.so
   #/home/vdudouyt/src/c-ares-1.27.0/obj-x86_64-linux-gnu/lib/x86_64-linux-gnu/libcares.so
)
