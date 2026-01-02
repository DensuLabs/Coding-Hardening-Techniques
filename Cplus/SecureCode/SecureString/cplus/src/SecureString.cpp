#include "include/SecureString.hpp"
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <cstring> // for memset_s (if available)

class SecureString 
{
private:
    std::vector<char> data;

    // Securely wipe memory (portable fallback if memset_s is unavailable)
    static void secure_wipe(void* ptr, size_t len) noexcept {
#if defined(__STDC_LIB_EXT1__)
        // C11 memset_s guaranteed not to be optimized away
        memset_s(ptr, len, 0, len);
#else
        volatile char* p = reinterpret_cast<volatile char*>(ptr);
        while (len--) {
            *p++ = 0;
        }
#endif
    }

public:
    explicit SecureString(const std::string& str) 
    {
        data.resize(str.size() + 1);
        std::copy(str.begin(), str.end(), data.begin());
        data[str.size()] = '\0';
    }

    // Disable copying
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;

    // Enable moving
    SecureString(SecureString&& other) noexcept : data(std::move(other.data)) 
    {
        other.secure_wipe(other.data.data(), other.data.size());
        other.data.clear();
    }

    SecureString& operator=(SecureString&& other) noexcept 
    {
        if (this != &other) {
            // Wipe existing data first
            secure_wipe(data.data(), data.size());

            data = std::move(other.data);
            other.secure_wipe(other.data.data(), other.data.size());
            other.data.clear();
        }
        return *this;
    }

    ~SecureString() 
    {
        secure_wipe(data.data(), data.size());
    }

    const char* c_str() const noexcept { return data.data(); }
    size_t size() const noexcept { return data.size() ? data.size() - 1 : 0; }
};
