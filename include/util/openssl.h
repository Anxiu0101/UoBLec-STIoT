#ifndef OPENSSL_H
#define OPENSSL_H

#include <openssl/ssl.h>
#include <openssl/err.h>

// Initialize OpenSSL
void openssl_init();

#endif // OPENSSL_H