#include "include/SecureBuffer.hpp"
#include <algorithm>

// Securely wipes a memory buffer to prevent sensitive data from lingering.
//
// This is critical for security-sensitive applications (e.g., cryptography,
// password handling). It ensures that data is overwritten with zeros and
// can't be recovered by attackers. The use of 'volatile' is key, as it
// prevents the compiler from optimizing away the write operations, which
// would otherwise be seen as unnecessary if the memory is immediately
// deallocated.
//
// @param ptr A pointer to the memory buffer to be wiped.
// @param len The number of bytes to wipe.
void SecureBuffer::secure_wipe(void *ptr, size_t len) noexcept
{
    // Return early if the pointer is null or the length is zero.
    // This is a good practice to prevent crashes and unnecessary operations.
    if (!ptr || len == 0)
        return;

    // Use a 'volatile char*' pointer to ensure each byte write is not optimized out by the compiler.
    // 'volatile' tells the compiler that the value can change at any time due to external factors,
    // so it must read/write to the memory location for every access.
    volatile char *p = reinterpret_cast<volatile char *>(ptr);

    // Loop through each byte and overwrite it with a null character (0).
    // The `len--` in the `while` loop condition is a common and efficient
    // way to count down and iterate through the buffer.
    while (len--){
        *p++ = 0;
    }
}

// Constructor for SecureBuffer.
// It allocates a new buffer of a specified size and immediately zeroes it out.
// This is a crucial step for a secure buffer, as it ensures that the allocated
// memory doesn't contain any leftover, sensitive data from previous operations.
//
// @param s The size (in bytes) of the buffer to be created.
SecureBuffer::SecureBuffer(size_t s)
    // Use an initializer list to initialize member variables `data` and `size`.
    // This is generally more efficient and is the preferred method in C++.
    : data(std::make_unique<char[]>(s)), size(s)
{

    // Check if memory allocation was successful. `std::make_unique` will throw
    // `std::bad_alloc` on failure, but this check provides an extra layer of
    // defensive programming.
    if (data){
        // Use `std::fill` to efficiently overwrite the entire buffer with zeros.
        // This ensures the buffer is in a known, safe state from the moment of
        // its creation.
        std::fill(data.get(), data.get() + size, 0);
    }
}

// Move constructor for SecureBuffer.
// This is used to efficiently transfer ownership of the underlying memory buffer
// from one `SecureBuffer` object to another without a deep copy. This is critical
// for performance, especially with large buffers.
//
// @param other An rvalue reference to another `SecureBuffer` object. The `&&`
//              indicates that `other` is a temporary or soon-to-be-destroyed object.
SecureBuffer::SecureBuffer(SecureBuffer &&other) noexcept
    // Use `std::move` to transfer ownership of the `std::unique_ptr`.
    // This is a highly efficient operation, as it only involves copying a pointer,
    // not the entire buffer data. The `other.data` pointer is now null,
    // and `this->data` points to the original memory.
    : data(std::move(other.data)),
    
    // Explicitly set the size of the source object to zero.
    // This is crucial to prevent the destructor of the `other` object
    // from attempting to free the memory that has now been moved.
    // The `other` object is now in a valid, empty state.
    size(std::exchange(other.size, 0)) {
}

// Move assignment operator.
// This is used to transfer ownership of the data buffer from a source object
// to the current object, efficiently and without a deep copy. It is designed
// for security, as it first securely erases the current object's data.
//
// @param other An rvalue reference to the source SecureBuffer object.
// @return A reference to the current object (*this), enabling method chaining.
SecureBuffer& SecureBuffer::operator=(SecureBuffer &&other) noexcept
{
    // The "self-assignment check" is a standard practice to prevent issues
    if (this != &other) {
        // Step 1: Securely wipe the data of the current object.
        secure_wipe(data.get(), size);

        // Step 2: Swap the contents. `std::swap` is a powerful tool here.
        // It efficiently exchanges the pointers and sizes between the two objects.
        // The `other` object's data and size now hold the old values of `*this`.
        using std::swap;
        swap(data, other.data);
        swap(size, other.size);
    }
    return *this;
}

// Destructor for SecureBuffer.
// This function is automatically called when a SecureBuffer object goes out of scope,
// is explicitly deleted, or its lifetime ends for any reason.
SecureBuffer::~SecureBuffer()
{
    // Call the `secure_wipe` function to zero out the memory buffer.
    // This is a critical step for a secure buffer. It prevents sensitive data
    // from remaining in memory after the object is destroyed, which could
    // otherwise be recovered by an attacker.
    // The `unique_ptr`'s destructor will be called automatically after this
    // function finishes, handling the `delete[]` operation for the underlying data.
    secure_wipe(data.get(), size);
}

// Returns a non-const pointer to the managed buffer.
// This allows for modification of the buffer's contents.
char* SecureBuffer::data_ptr() noexcept
{
    return data.get();
}

// Overloaded `const` version of `data_ptr`.
// It returns a const pointer, indicating that the buffer's contents
// should not be modified through this pointer. This is a best practice
// for providing read-only access to internal data.
const char* SecureBuffer::data_ptr() const noexcept
{
    return data.get();
}

// Returns the size of the buffer in bytes.
// This is a simple accessor function that allows external code to query the
// size of the managed buffer.
//
// The `const` keyword at the end of the function signature guarantees that
// this method will not modify any member variables of the `SecureBuffer` object.
// The `noexcept` keyword indicates that the function is guaranteed not to throw
// any exceptions, which is a key part of writing robust, modern C++ code.
//
// @return The size of the buffer in bytes (type `size_t`).
size_t SecureBuffer::size_bytes() const noexcept
{
    // Return the value of the `size` member variable.
    return size;
}
