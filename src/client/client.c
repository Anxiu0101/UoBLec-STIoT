#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../../include/client.h"
#include "../../include/util/log.h"
#include "../../include/util/openssl.h"

#define BUFFER_SIZE 1024

SSL_CTX* client_init() {
    SSL_CTX *ctx;

    // Initialize OpenSSL
    openssl_init();

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void connect_to_server(SSL *ssl, const char *hostname, int port) {
    int server_fd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE] = {0};

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    // inet_pton(AF_INET, hostname, &server_addr.sin_addr);
    if (inet_pton(AF_INET, hostname, &server_addr.sin_addr) <= 0) {
        log_client("Invalid address");
        exit(EXIT_FAILURE);
    }

    // Connect to server
    log_client("Connecting to server...");
    if (connect(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect failed");
        exit(EXIT_FAILURE);
    }
    log_client("Connected to server successfully");

    // Associate socket with SSL object
    SSL_set_fd(ssl, server_fd);

    // SSL handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        log_client("SSL handshake failed");
    } else {
        log_client("SSL handshake successful");
        
        log_client("Please enter the message to send: ");
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = 0;  // Remove newline character

        log_client("Sending message to server...");
        SSL_write(ssl, buffer, strlen(buffer));

        memset(buffer, 0, BUFFER_SIZE);
        SSL_read(ssl, buffer, sizeof(buffer));
        log_client("Received from server: %s", buffer);
    }

    // Close connection
    log_client("Closing SSL connection...");
    SSL_shutdown(ssl);
    close(server_fd);
}

void cleanup(SSL_CTX *ctx) {
    SSL_CTX_free(ctx);
    EVP_cleanup();
}

int main(int argc, char **argv) {
    SSL_CTX *ctx;
    SSL *ssl;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <hostname>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Initialize client
    ctx = client_init();
    ssl = SSL_new(ctx);

    // Connect to server
    connect_to_server(ssl, argv[1], 4433);

    // Clean up
    SSL_free(ssl);
    cleanup(ctx);

    return 0;
}
