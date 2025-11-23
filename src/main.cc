#include <iostream>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

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

class LolTest: public ::testing::Test {
protected:
   void SetUp() {
      std::cout << "SetUp()" << std::endl;
      value = 10;
   }
   void TearDown() {
      std::cout << "TearDown()" << std::endl;
   }
   int value;
};

// A simple function to test
int Add(int a, int b) {
    return a + b;
}

TEST_F(LolTest, Add) {
    EXPECT_EQ(Add(2, 3), 5);
    EXPECT_NE(Add(2, 2), 5);
    EXPECT_EQ(value, 10);
    MockHelloSayer mock;
    EXPECT_CALL(mock, SayHello());
    mock.SayHello();
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
