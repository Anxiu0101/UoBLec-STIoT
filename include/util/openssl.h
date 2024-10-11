#ifndef OPENSSL_H
#define OPENSSL_H

#include <openssl/ssl.h>
#include <openssl/err.h>

// Initialize OpenSSL
void openssl_init();
// Cleanup OpenSSL
void cleanup(SSL_CTX *ctx);

#endif // OPENSSL_H
