# Makefile for compiling 'server' and 'client'

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall

# Source files
SERVER_SRC = rdp.c
CLIENT_SRC = rdp_client.c

# Target executables
SERVER_TARGET = server
CLIENT_TARGET = client

# Default target
all: $(SERVER_TARGET) $(CLIENT_TARGET)

# Rule to create the server executable
$(SERVER_TARGET): $(SERVER_SRC)
	$(CC) $(CFLAGS) $(SERVER_SRC) -o $(SERVER_TARGET)

# Rule to create the client executable
$(CLIENT_TARGET): $(CLIENT_SRC)
	$(CC) $(CFLAGS) $(CLIENT_SRC) -o $(CLIENT_TARGET)

# Rule for cleaning up
clean:
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET)

# Phony targets
.PHONY: all clean server_target client_target

# Individual targets for server and client
server_target: $(SERVER_TARGET)
client_target: $(CLIENT_TARGET)
