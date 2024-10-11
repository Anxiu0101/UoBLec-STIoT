#ifndef SERVER_H
#define SERVER_H

#include <openssl/ec.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Initialize server
int server_init(int port);

// Handle client connection
void handle_client(SSL *ssl);

#endif
