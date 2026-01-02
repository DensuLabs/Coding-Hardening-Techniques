#ifndef SECUREBUFFER_HPP
#define SECUREBUFFER_HPP

#include <memory>
#include <cstddef> // for std::byte

// RAII Secure Buffer
class SecureBuffer
{
private:
    std::unique_ptr<char[]> data;
    size_t size;

    static void secure_wipe(void *ptr, size_t len) noexcept;

public:
    explicit SecureBuffer(size_t s);

    // Disable copying
    SecureBuffer(const SecureBuffer &) = delete;
    SecureBuffer &operator=(const SecureBuffer &) = delete;

    // Enable moving
    SecureBuffer(SecureBuffer &&other) noexcept;
    SecureBuffer &operator=(SecureBuffer &&other) noexcept;

    ~SecureBuffer();

    // Accessors
    char *data_ptr() noexcept;
    const char *data_ptr() const noexcept;
    size_t size_bytes() const noexcept;
};

#endif // SECUREBUFFER_HPP