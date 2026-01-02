#ifndef SECURESTRING_HPP
#define SECURESTRING_HPP

// RAII Secure String
class SecureString
{
private:
    static void secure_wipe(void *ptr, size_t len) noexcept;

public:
explicit SecureString(size_t s);

// Disable copying
SecureString(const SecureString &) = delete;
SecureString &operator=(const SecureString &) = delete;

// Enable moving
SecureString(SecureString &&other) noexcept;
SecureString &operator=(SecureString &&other) noexcept;

~SecureString();

};
#endif // SECURESTRING_HPP