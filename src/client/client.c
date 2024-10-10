#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>   
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../../include/client.h"
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

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        // perror("Unable to create SSL context");
        log_client("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int main() {
    int sockfd;
    struct sockaddr_in addr;
    SSL_CTX *ctx;
    SSL *ssl;

    initialize_openssl();
    ctx = create_context();

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        // perror("Unable to create socket");
        log_client("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    printf("Connecting to server\n");
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        // perror("Unable to connect");
        log_client("Unable to connect");
        exit(EXIT_FAILURE);
    }
    printf("Connected to server\n");

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    printf("Starting SSL handshake\n");
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        log_client("SSL handshake failed");
    } else {;
        log_client("SSL handshake successful");
        char buffer[BUFFER_SIZE] = {0};
        printf("Enter a message: ");
        fgets(buffer, BUFFER_SIZE, stdin);

        printf("Sending message to server\n");
        SSL_write(ssl, buffer, strlen(buffer));
        // printf("Waiting for server response\n");
        log_client("Waiting for server response");
        SSL_read(ssl, buffer, sizeof(buffer));
        // printf("Server response: %s\n", buffer);
        log_client("Server response: %s", buffer);
    }

    log_client("Closing SSL connection");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    log_client("SSL connection closed");
    close(sockfd);
    log_client("Socket closed");
    SSL_CTX_free(ctx);
    log_client("SSL context freed");
    cleanup_openssl();
    log_client("OpenSSL cleaned up");
    return 0;
}
