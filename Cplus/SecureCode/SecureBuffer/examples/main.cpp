#include "include/SecureBuffer.hpp"
#include <iostream>
#include <cstring> // for std::memcpy

int main() {
    std::cout << "=== SecureBuffer Demo ===\n";

    // Create a buffer of 32 bytes
    SecureBuffer buf1(32);
    std::cout << "[1] Buffer created, size = " << buf1.size_bytes() << " bytes\n";

    // Write some data
    const char* msg = "SensitiveData";
    std::memcpy(buf1.data_ptr(), msg, std::strlen(msg) + 1);
    std::cout << "[2] Buffer contains: " << buf1.data_ptr() << "\n";

    // Move the buffer into another
    SecureBuffer buf2 = std::move(buf1);
    std::cout << "[3] Moved buffer, size = " << buf2.size_bytes() << " bytes\n";
    std::cout << "[4] Moved buffer contains: " << buf2.data_ptr() << "\n";

    // Check original buffer after move
    std::cout << "[5] Original buffer size after move = " << buf1.size_bytes() << " bytes\n";

    std::cout << "=== End of demo, destructors will securely wipe memory ===\n";
    return 0;
}