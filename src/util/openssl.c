#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../../include/util/openssl.h"

// Initialize OpenSSL
// call SSL_library_init()
// call OpenSSL_add_all_algorithms()
// call SSL_load_error_strings()
void openssl_init() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

// Cleanup OpenSSL
// call SSL_CTX_free(ctx)
// call EVP_cleanup()
void cleanup(SSL_CTX *ctx) {
    SSL_CTX_free(ctx);
    EVP_cleanup();
}