CC = gcc
CFLAGS = -Wall -O2 -I./include
LIBS = -lssl -lcrypto

SRC_DIR = src
BIN_DIR = bin
INCLUDE_DIR = include

UTIL_SRC = $(SRC_DIR)/util/log.c $(SRC_DIR)/util/openssl.c

SERVER_SRC = $(SRC_DIR)/server/server.c $(UTIL_SRC)
CLIENT_SRC = $(SRC_DIR)/client/client.c $(UTIL_SRC)

$(shell mkdir -p $(BIN_DIR))

build: $(BIN_DIR)/server $(BIN_DIR)/client

$(BIN_DIR)/server: $(SERVER_SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

$(BIN_DIR)/client: $(CLIENT_SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -rf $(BIN_DIR)

.PHONY: build clean