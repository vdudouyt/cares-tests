#include <iostream>
#include <ares.h>
#include <cstddef>
#include <netdb.h>
#include "dns-proto.h"
#include "ares-test.h"

using ::testing::_;
using ::testing::Return;

class IHelloSayer {
public:
   virtual void SayHello() = 0;
};

class MockHelloSayer: public IHelloSayer {
public:
   MOCK_METHOD(void, SayHello, (), (override));
};

int main(int argc, char **argv) {
    if(argc != 2) {
        fprintf(stderr, "Wrong usage\n");
        exit(-1);
    }
    ::testing::InitGoogleTest(&argc, argv);
    load_cares_impl(argv[1]);
    int res = RUN_ALL_TESTS();
    unload_cares_impl();
    return res;
}
