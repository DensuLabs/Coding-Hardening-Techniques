#include "include/secure_buffer.h"
#include <stdio.h>

int main()
{
    SecureBuffer buf;

    if (SecureBuffer_init(&buf, 32) != 0){
        fprintf(stderr, "Failed to allocate buffer\n");
        return 1;
    }

    SecureBuffer_write(&buf, "Hello Secure C Buffer!", 23);
    SecureBuffer_print(&buf);
    SecureBuffer_free(&buf);
    return 0;
}