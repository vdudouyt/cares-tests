cmake_minimum_required(VERSION 3.10)
project(SimpleGTest)

set(CMAKE_CXX_STANDARD 11)

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

add_executable(sample_test src/main.cc src/loader.cc src/dns-proto.cc src/ares-test.cc src/ares-test-parse-a.cc src/ares-test-parse-aaaa.cc src/ares-test-parse-caa.cc src/ares-test-parse-mx.cc src/ares-test-parse-naptr.cc src/ares-test-parse-ns.cc src/ares-test-parse-ptr.cc src/ares-test-parse-soa-any.cc src/ares-test-parse-soa.cc src/ares-test-parse-srv.cc src/ares-test-parse-txt.cc src/ares-test-parse-uri.cc src/ares-test-live.cc)
target_link_libraries(sample_test GTest::GTest GTest::Main GTest::gmock pthread
   #/home/vdudouyt/git/cares-rs/target/debug/libcares_rs.so
   #/home/vdudouyt/src/c-ares-1.27.0/obj-x86_64-linux-gnu/lib/x86_64-linux-gnu/libcares.so
)
