# Secure Transfer IoT (C and OpenSSL)

This is a simple secure file transfer program using C and OpenSSL. It consists of two parts:
- A server that listens for connections.
- A client that connects to the server and sends a message.

## How to compile and run the program

1. Make sure you have OpenSSL installed on your system.
    - You need to initialize the keys and certificates first.
    ```shell
    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
    ```
    - The `server.key` is the private key and the `server.crt` is the public key.
    - x509 is the certificate format.
    - rsa:4096 is the key length.
    - days is the validity period of the certificate.
    - nodes is the number of nodes in the certificate.
2. Run `make build` to compile the project.
3. To start the server, run `./build/server`.
4. To connect as a client, run `./build/client`.

## Requirements

- C compiler (gcc)
- OpenSSL library

## TODO

- [ ] 修复 colorized perror 包装
- [ ] 将加密算法更改为 ECC，签名算法修改 ECDSA，密钥交换改为 ECDH
- [ ] 命令行封装
- [ ] 服务连接可配置，使用 toml 配置
- [ ] 处理服务端为服务端提供消息队列，提高服务端的多链接处理能力。
