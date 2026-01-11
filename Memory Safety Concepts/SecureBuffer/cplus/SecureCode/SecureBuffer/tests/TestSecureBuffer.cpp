#include <gtest/gtest.h>
#include "include/SecureBuffer.hpp"
#include <cstring> // for std::memcpy

// Test: constructor initializes buffer with zeros
TEST(SecureBufferTest, InitializesWithZeros) {
    SecureBuffer buf(16);
    for (size_t i = 0; i < buf.size_bytes(); ++i) {
        EXPECT_EQ(buf.data_ptr()[i], 0);
    }
}

// Test: buffer can store and retrieve data
TEST(SecureBufferTest, StoresAndRetrievesData) {
    SecureBuffer buf(32);
    const char* msg = "HelloWorld";
    std::memcpy(buf.data_ptr(), msg, std::strlen(msg) + 1);

    EXPECT_STREQ(buf.data_ptr(), msg);
}

// Test: move constructor transfers ownership
TEST(SecureBufferTest, MoveConstructor) {
    SecureBuffer buf1(16);
    const char* msg = "MoveTest";
    std::memcpy(buf1.data_ptr(), msg, std::strlen(msg) + 1);

    SecureBuffer buf2 = std::move(buf1);

    EXPECT_EQ(buf2.size_bytes(), 16);
    EXPECT_STREQ(buf2.data_ptr(), "MoveTest");
    EXPECT_EQ(buf1.size_bytes(), 0); // original should be empty
}

// Test: move assignment transfers ownership
TEST(SecureBufferTest, MoveAssignment) {
    SecureBuffer buf1(16);
    SecureBuffer buf2(32);

    const char* msg = "AssignTest";
    std::memcpy(buf1.data_ptr(), msg, std::strlen(msg) + 1);

    buf2 = std::move(buf1);

    EXPECT_EQ(buf2.size_bytes(), 16);
    EXPECT_STREQ(buf2.data_ptr(), "AssignTest");
    EXPECT_EQ(buf1.size_bytes(), 0);
}