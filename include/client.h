#ifndef CLIENT_H
#define CLIENT_H

#include <openssl/ssl.h>
#include <openssl/err.h>

// 客户端配置结构体
typedef struct {
    const char* server_ip;
    int server_port;
    const char* ca_file;
} ClientConfig;

// 初始化客户端
int client_init(ClientConfig* config);

// 连接到服务器
int client_connect();

// 发送消息
int client_send_message(const char* message);

// 接收消息
int client_receive_message(char* buffer, int buffer_size);

// 断开连接
void client_disconnect();

// 清理客户端资源
void client_cleanup();

#endif // CLIENT_H