#include "server.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../../include/server.h"
#include "../../include/util/log.h"
#include "../../include/util/openssl.h"

int server_init(int port) {
    int server_fd;
    struct sockaddr_in server_addr;

    // Create server socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Set server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // Bind server socket
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return -1;
    }

    // Listen for connections
    if (listen(server_fd, 1) < 0) {
        perror("Listen failed");
        close(server_fd);
        return -1;
    }

    return server_fd;
}

void handle_client(SSL *ssl) {
    char buffer[1024] = {0};
    int bytes;

    // Read message from client
    bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes > 0) {
        printf("Received: %s\n", buffer);
        // Reply to client
        SSL_write(ssl, "Message received", strlen("Message received"));
    } else {
        printf("Failed to read message\n");
    }
}

void cleanup(SSL_CTX *ctx) {
    SSL_CTX_free(ctx);
    EVP_cleanup();
}

int main(int argc, char **argv) {
    SSL_CTX *ctx;
    SSL *ssl;
    int server_fd, client_fd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Initialize OpenSSL
    openssl_init();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load server ECC certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "cert/server-cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "cert/server-key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Initialize server
    server_fd = server_init(4433);
    if (server_fd < 0) {
        perror("Server initialization failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port 4433...\n");

    while(1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        SSL *ssl;

        // Accept client connection
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            log_server("Accept connection failed");
            continue;
        }

        // Create SSL object
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        log_server("Start SSL handshake");

        // Perform SSL handshake
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            log_server("SSL handshake failed");
        } else {
            log_server("SSL handshake success");
            handle_client(ssl);
        }

        // Close SSL connection
        log_server("Close SSL connection");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    cleanup(ctx);
    close(server_fd);

    return 0;
}
