#include "include/secure_buffer.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Initialize buffer with zeroed memory
int SecureBuffer_init(SecureBuffer *buf, size_t size)
{
    if (!buf)
        return -1;
    buf->data = (char *)malloc(size);
    if (!buf->data)
        return -1;
    memset(buf->data, 0, size);
    buf->size = size;
    return 0;
}

// Securely clear memory before freeing
void SecureBuffer_free(SecureBuffer *buf)
{
    if (buf && buf->data){
        memset(buf->data, 0, buf->size); // wipe memory
        free(buf->data);
        buf->data = NULL;
        buf->size = 0;
    }
}

// Write data into buffer
int SecureBuffer_write(SecureBuffer *buf, const char *src, size_t len)
{
    if (!buf || !buf->data || len > buf->size)
        return -1;
    memcpy(buf->data, src, len);
    return 0;
}

// Print buffer safely
void SecureBuffer_print(const SecureBuffer *buf)
{
    if (!buf || !buf->data)
        return;
    fwrite(buf->data, 1, buf->size, stdout);
    putchar('\n');
}