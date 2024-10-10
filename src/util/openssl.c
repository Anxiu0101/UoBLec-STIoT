#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../../include/util/openssl.h"

// Initialize OpenSSL
void openssl_init() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}