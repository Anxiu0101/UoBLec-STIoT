#ifndef SERVER_H
#define SERVER_H

#include <openssl/ssl.h>
#include <openssl/err.h>

// 服务器配置结构体
typedef struct {
    int port;
    const char* cert_file;
    const char* key_file;
} ServerConfig;

// 初始化服务器
int server_init(ServerConfig* config);

// 启动服务器
int server_start();

// 停止服务器
void server_stop();

// 清理服务器资源
void server_cleanup();

#endif // SERVER_H