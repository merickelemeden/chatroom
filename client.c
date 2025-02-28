// client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "config.h"

void *receive_messages(void *socket_desc) {
    int sock = *(int *)socket_desc;
    char buffer[BUFFER_SIZE];

    while (1) {
        int len = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (len <= 0) {
            printf("Disconnected from server.\n");
            exit(0); // Terminate the entire program
        }
        buffer[len] = '\0';
        printf("%s", buffer);
    }
}

int main(int argc, char* argv[]) {
    // Default values from config.h
    char server_ip[INET_ADDRSTRLEN] = SERVER_IP; // Default IP (127.0.0.1)
    int port = SERVER_PORT;                     // Default port (8888)

    // Parse command-line arguments
    if (argc == 2) {
        // If only one argument, assume it's the port
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port number: %s\n", argv[1]);
            return 1;
        }
    } else if (argc == 3) {
        // If two arguments, assume first is IP and second is port
        strncpy(server_ip, argv[1], INET_ADDRSTRLEN - 1);
        server_ip[INET_ADDRSTRLEN - 1] = '\0'; // Ensure null-termination
        port = atoi(argv[2]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port number: %s\n", argv[2]);
            return 1;
        }
    } else if (argc > 3) {
        fprintf(stderr, "Usage: %s [server_ip] [port]\n", argv[0]);
        return 1;
    }

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Could not create socket");
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Validate and set IP address
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IP address: %s\n", server_ip);
        close(sock);
        return 1;
    }

    printf("Connecting to server at %s:%d...\n", server_ip, port);
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Connection failed");
        close(sock);
        return 1;
    }

    // Create thread to receive messages
    pthread_t recv_thread;
    if (pthread_create(&recv_thread, NULL, receive_messages, &sock) != 0) {
        perror("Could not create thread");
        close(sock);
        return 1;
    }

    // Send messages to server
    char message[BUFFER_SIZE];
    while (1) {
        if (fgets(message, sizeof(message), stdin) != NULL) {
            send(sock, message, strlen(message), 0);
        }
    }

    close(sock);
    return 0;
}
