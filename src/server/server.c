#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../../include/server.h"
#include "../../include/util/log.h"

#define PORT 4443
#define BUFFER_SIZE 1024

void initialize_openssl() {
    SSL_load_error_strings();   
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);

    // Error Handling
    // If the context is not created, 
    // print the error and exit.
    if (!ctx) {
        log_server("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    // Load your certificate and private key files
    if (SSL_CTX_use_certificate_file(ctx, "cert/server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "cert/server.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main() {
    int sockfd;
    struct sockaddr_in addr;
    SSL_CTX *ctx;

    initialize_openssl();
    ctx = create_context();

    configure_context(ctx);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    while(1) {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        SSL *ssl;
        int client = accept(sockfd, (struct sockaddr*)&addr, &len);

        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        log_server("SSL connection using %s", SSL_get_cipher(ssl));
        log_server("Starting SSL handshake");

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            log_server("SSL handshake failed");
        } else {
            log_server("SSL handshake successful");
            char buffer[BUFFER_SIZE] = {0};
            int bytes;

            bytes = SSL_read(ssl, buffer, sizeof(buffer));
            if (bytes > 0) {
                log_server("Received: %s", buffer);
                SSL_write(ssl, "Message received", strlen("Message received"));
            }
        }

        log_server("Closing SSL connection");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
        log_server("SSL connection closed");
    }

    close(sockfd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
