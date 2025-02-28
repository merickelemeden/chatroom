#ifndef CONFIG_H
#define CONFIG_H

// Define server IP and port
#define SERVER_IP "0.0.0.0"  // Localhost for testing
#define SERVER_PORT 8080       // Port number for the server

// Buffer sizes
#define BUFFER_SIZE 1024   // General buffer size for messages
#define MAX_CLIENTS 100    // Maximum number of clients that can connect
#define MAX_USERS_IN_ROOM 10 
#define NAME_LEN 16        // Maximum length of a username
#define MAX_MESSAGE_LENGTH 256 

// File paths
#define USERS_FILE "users.txt"       // File to store registered users
#define ADMINS_FILE "admins.txt"     // File to store admins
#define MUTED_FILE "muted_users.txt" // File to store muted users
#define BANNED_FILE "banned_users.txt" // File to store banned users
#define IGNORES_FILE "ignores.txt"   // File to store ignored users

// Timeout settings
#define CONNECTION_TIMEOUT 300 // Time in seconds before disconnecting idle clients

#endif // CONFIG_H
