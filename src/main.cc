#include <gtest/gtest.h>

// A simple function to test
int Add(int a, int b) {
    return a + b;
}

TEST(MathTest, Add) {
    EXPECT_EQ(Add(2, 3), 5);
    EXPECT_NE(Add(2, 2), 5);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
