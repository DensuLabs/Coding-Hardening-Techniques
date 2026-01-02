#ifndef SECURE_BUFFER_H
#define SECURE_BUFFER_H

#include <stddef.h>

// Struct definition
typedef struct {
    char *data;
    size_t size;
} SecureBuffer;

// API functions
int SecureBuffer_init(SecureBuffer *buf, size_t size);
void SecureBuffer_free(SecureBuffer *buf);
int SecureBuffer_write(SecureBuffer *buf, const char *src, size_t len);
void SecureBuffer_print(const SecureBuffer *buf);

#endif // SECURE_BUFFER_H
