# SecureTransferIoT(STIoT): Secure Communication Implementation for IoT Devices

**SecureTransferIoT(STIoT)** is a secure communication project based on OpenSSL, specifically designed for Internet of Things (IoT) devices. This project implements a simple client-server model, utilizing the TLS protocol to ensure secure communications.

## Features

- Implements TLS-encrypted communication using the OpenSSL library
- Supports continuous server listening for multiple client connections
- Clients can input messages from the command line and send them to the server
- Uses ECC (Elliptic Curve Cryptography) certificates for authentication
- Includes comprehensive logging functionality

## Compilation Instructions

Ensure that the <u>OpenSSL development library</u> is installed on your system. Then, compile the project using the following command:

```shell
make build
```

This will generate two executable files: `server` and `client` in the `bin/` directory.

## Usage

### Server

To start the server, run the following command:

```shell
./bin/server
```

Server will listen for connections on port `4433`.

### Client

To connect as a client, run the following command:

```shell
./bin/client <server_address>
./bin/client 127.0.0.1 # for example
```

Replace `<server_address>` with the IP address or hostname of the server.

After connecting, you can input messages to send to the server.

Server will receive messages and print them to the console.


## Security Considerations

- This project uses ECC certificates for authentication. Ensure the use of properly signed certificates in real-world deployments.
    - For the sake of simplicity, certificate authorities are not implemented. In a real-world scenario, you would need to set up a proper certificate authority and use it to sign the server's certificate.
    - Generate server's private key and self-signed certificate:
    ```shell
    openssl ecparam -genkey -name prime256v1 -out server-key.pem
    openssl req -new -x509 -key server-key.pem -out server-cert.pem -days 365
    ```
- Regularly update the OpenSSL library to receive the latest security patches.
- In a production environment, consider implementing certificate verification and revocation checking.

## License & Contributions

This project is licensed under the MIT License. See the LICENSE file for details.

Issues and pull requests to improve this project are welcome.
