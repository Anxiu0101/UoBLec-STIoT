#ifndef CLIENT_H
#define CLIENT_H

#include <openssl/ec.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Initialize client
SSL_CTX* client_init();

// Handle connection to server
void connect_to_server(SSL *ssl, const char *hostname, int port);

// Release resources
void cleanup(SSL_CTX *ctx);

#endif
