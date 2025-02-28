#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>
#include "config.h"

typedef struct
{
    int socket;
    struct sockaddr_in address;
    char name[NAME_LEN];
    int authenticated; // 1 if the client is authenticated
    int is_admin;      // 1 if the client is an admin
    int muted;         // 1 if the client is muted
    int ignores[MAX_USERS_IN_ROOM];
} client_t;

// ============= GLOBALS =============
client_t *clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
char logged_in_users[MAX_USERS_IN_ROOM][NAME_LEN];

// ============= FORWARD DECLS =============
void *handle_client(void *arg);
void handle_command(client_t *client, const char *command);

// File-based helpers
int is_user_banned(const char *username);
void ban_user(const char *username);
void unban_user(const char *username);

int is_user_muted(const char *username);
void mute_user(const char *username);
void unmute_user(const char *username);

void load_ignores_for_user(client_t *client);
void add_ignore_in_file(const char *ignorer, const char *ignoree);
void remove_ignore_in_file(const char *ignorer, const char *ignoree);

// Already existing or partial
int is_user_registered(const char *username);
int register_user(const char *username, const char *password);
int authenticate_user(const char *username, const char *password);
int is_user_logged_in(const char *username);
void add_logged_in_user(const char *username);
void remove_logged_in_user(const char *username);
client_t *find_client_by_name(const char *username);
int is_user_admin(const char *username);
void promote_user(client_t *c);
void demote_user(client_t *c);
void add_admin_to_file(const char *username);
void remove_admin_from_file(const char *username);

// ============= BROADCAST (checks ignoring) =============
void broadcast_message(const char *message, int sender_socket)
{
    pthread_mutex_lock(&clients_mutex);
    // Identify sender
    client_t *sender = NULL;
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (clients[i] && clients[i]->socket == sender_socket)
        {
            sender = clients[i];
            break;
        }
    }

    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        client_t *c = clients[i];
        if (!c || !c->authenticated)
            continue;
        if (c->socket == sender_socket)
            continue;

        // Check if c is ignoring the sender
        if (sender)
        {
            // Find sender index in logged_in_users
            int senderIndex = -1;
            for (int u = 0; u < MAX_USERS_IN_ROOM; u++)
            {
                if (strcmp(logged_in_users[u], sender->name) == 0)
                {
                    senderIndex = u;
                    break;
                }
            }
            if (senderIndex >= 0 && c->ignores[senderIndex] == 1)
            {
                // c is ignoring the sender
                continue;
            }
        }

        // Send
        send(c->socket, message, strlen(message), 0);
    }
    pthread_mutex_unlock(&clients_mutex);
}
// Check if a user is already registered
int is_user_registered(const char *username)
{
    FILE *file = fopen(USERS_FILE, "r");
    if (!file)
        return 0;

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file))
    {
        char stored_username[NAME_LEN];
        sscanf(line, "%31s", stored_username);
        if (strcmp(stored_username, username) == 0)
        {
            fclose(file);
            return 1; // User exists
        }
    }

    fclose(file);
    return 0;
}

// Register a new user
int register_user(const char *username, const char *password)
{
    if (is_user_registered(username))
    {
        return 0; // User already exists
    }

    FILE *file = fopen(USERS_FILE, "a");
    if (!file)
        return -1;

    fprintf(file, "%s %s\n", username, password);
    fclose(file);
    return 1; // Registration successful
}

// Authenticate a user
int authenticate_user(const char *username, const char *password)
{
    FILE *file = fopen(USERS_FILE, "r");
    if (!file)
        return 0;

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file))
    {
        char stored_username[NAME_LEN], stored_password[BUFFER_SIZE];
        sscanf(line, "%31s %1023s", stored_username, stored_password);
        if (strcmp(stored_username, username) == 0 && strcmp(stored_password, password) == 0)
        {
            fclose(file);
            return 1; // Authentication successful
        }
    }

    fclose(file);
    return 0; // Authentication failed
}

int is_user_logged_in(const char *username)
{
    for (int i = 0; i < MAX_USERS_IN_ROOM; i++)
    {
        if (strcmp(logged_in_users[i], username) == 0)
        {
            return 1; // User is already logged in
        }
    }
    return 0; // User is not logged in
}

void add_logged_in_user(const char *username)
{
    for (int i = 0; i < MAX_USERS_IN_ROOM; i++)
    {
        if (logged_in_users[i][0] == '\0')
        { // Empty slot
            strncpy(logged_in_users[i], username, NAME_LEN - 1);
            logged_in_users[i][NAME_LEN - 1] = '\0'; // Ensure null-termination
            break;
        }
    }
}

void remove_logged_in_user(const char *username)
{
    for (int i = 0; i < MAX_USERS_IN_ROOM; i++)
    {
        if (strcmp(logged_in_users[i], username) == 0)
        {
            logged_in_users[i][0] = '\0'; // Mark as empty
            break;
        }
    }
}
client_t *find_client_by_name(const char *username)
{
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (clients[i] && clients[i]->authenticated && strcmp(clients[i]->name, username) == 0)
        {
            pthread_mutex_unlock(&clients_mutex);
            return clients[i];
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    return NULL; // User not found
}

int is_user_admin(const char *username)
{
    FILE *file = fopen("admins.txt", "r");
    if (!file)
        return 0;

    char line[NAME_LEN];
    while (fgets(line, sizeof(line), file))
    {
        line[strcspn(line, "\n")] = '\0'; // Remove newline
        if (strcmp(line, username) == 0)
        {
            fclose(file);
            return 1; // User is an admin
        }
    }

    fclose(file);
    return 0; // User is not an admin
}

void promote_user(client_t *client)
{
    client->is_admin = 1;
}

void demote_user(client_t *client)
{
    client->is_admin = 0;
}

void add_admin_to_file(const char *username)
{
    FILE *file = fopen(ADMINS_FILE, "a");
    if (file)
    {
        fprintf(file, "%s\n", username); // Append the username
        fclose(file);
    }
}

void remove_admin_from_file(const char *username)
{
    FILE *file = fopen(ADMINS_FILE, "r");
    if (!file)
        return;

    char line[NAME_LEN];
    char temp_file[] = "admins_tmp.txt";

    FILE *temp = fopen(temp_file, "w");
    if (!temp)
    {
        fclose(file);
        return;
    }

    // Copy all lines except the one to be removed
    while (fgets(line, sizeof(line), file))
    {
        line[strcspn(line, "\n")] = '\0'; // Remove newline
        if (strcmp(line, username) != 0)
        {
            fprintf(temp, "%s\n", line);
        }
    }

    fclose(file);
    fclose(temp);

    // Replace the original file with the temporary file
    remove(ADMINS_FILE);
    rename(temp_file, ADMINS_FILE);
}
// ============= MAIN LISTEN LOOP =============
int main(int argc, char *argv[])
{
    int simpleSocket = 0, simpleChildSocket = 0;
    int simplePort = SERVER_PORT;
    struct sockaddr_in simpleServer, clientName;
    socklen_t clientNameLength = sizeof(clientName);

    // Zero out the logged_in_users
    for (int i = 0; i < MAX_USERS_IN_ROOM; i++)
    {
        logged_in_users[i][0] = '\0';
    }
    // Zero out clients
    memset(clients, 0, sizeof(clients));

    if (argc == 2)
    {
        simplePort = atoi(argv[1]);
    }

    simpleSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (simpleSocket == -1)
    {
        perror("Could not create a socket");
        exit(1);
    }

    memset(&simpleServer, 0, sizeof(simpleServer));
    simpleServer.sin_family = AF_INET;
    simpleServer.sin_addr.s_addr = htonl(INADDR_ANY);
    simpleServer.sin_port = htons(simplePort);

    if (bind(simpleSocket, (struct sockaddr *)&simpleServer, sizeof(simpleServer)) == -1)
    {
        perror("Could not bind to address");
        close(simpleSocket);
        exit(1);
    }

    // **Debugging: Confirm Bound Address**
    struct sockaddr_in boundAddr;
    socklen_t boundAddrLen = sizeof(boundAddr);
    if (getsockname(simpleSocket, (struct sockaddr *)&boundAddr, &boundAddrLen) == -1) {
        perror("getsockname failed");
    } else {
        printf("Server bound to %s:%d\n", inet_ntoa(boundAddr.sin_addr), ntohs(boundAddr.sin_port));
    }
    
    if (listen(simpleSocket, 10) == -1)
    {
        perror("Could not listen for connections");
        close(simpleSocket);
        exit(1);
    }
    else
    {
        printf("Server started successfully on port %d\n", simplePort);
    }

    while (1)
    {
        simpleChildSocket = accept(simpleSocket, (struct sockaddr *)&clientName, &clientNameLength);
        if (simpleChildSocket == -1)
        {
            perror("Cannot accept connections");
            continue;
        }

        pthread_mutex_lock(&clients_mutex);

        // Find a free slot
        int found_slot = 0;
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (!clients[i])
            {
                client_t *client = (client_t *)malloc(sizeof(client_t));
                memset(client, 0, sizeof(client_t));
                client->socket = simpleChildSocket;
                client->address = clientName;
                clients[i] = client;
                found_slot = 1;

                // Immediately send a banner / usage info
                const char *banner =
                    "---------- Chatroom 1.0 ----------\n"
                    "Use /help to see available commands.\n";
                send(simpleChildSocket, banner, strlen(banner), 0);

                // Create the thread
                pthread_t tid;
                if (pthread_create(&tid, NULL, handle_client, (void *)client) != 0)
                {
                    perror("Failed to create thread");
                }
                break;
            }
        }

        if (!found_slot)
        {
            // No room for new clients
            const char *full_msg = "Server is full. Try again later.\n";
            send(simpleChildSocket, full_msg, strlen(full_msg), 0);
            close(simpleChildSocket);
        }

        pthread_mutex_unlock(&clients_mutex);
    }

    close(simpleSocket);
    return 0;
}

// ============= THREAD: HANDLE CLIENT =============
void *handle_client(void *arg)
{
    client_t *client = (client_t *)arg;
    char buffer[BUFFER_SIZE];

    while (1)
    {
        int receive = recv(client->socket, buffer, BUFFER_SIZE - 1, 0);
        if (receive <= 0)
        {
            // Socket closed or error
            break;
        }
        buffer[receive] = '\0';

        if (strlen(buffer) > 0)
        {
            if (buffer[0] == '/')
            {
                // Command
                handle_command(client, buffer);
                // Possibly /leave or /kick closed the socket
                if (client->socket == -1)
                    break;
            }
            else
            {
                // Normal message
                if (!client->authenticated)
                {
                    const char *not_auth = "Please register or login to send messages.\n";
                    send(client->socket, not_auth, strlen(not_auth), 0);
                    continue;
                }
                // If muted
                if (client->muted)
                {
                    const char *muted_msg = "You are muted and cannot send messages.\n";
                    send(client->socket, muted_msg, strlen(muted_msg), 0);
                    continue;
                }
                // Check size
                if (strlen(buffer) > MAX_MESSAGE_LENGTH)
                {
                    const char *err = "Message too long. Limit is 256 characters.\n";
                    send(client->socket, err, strlen(err), 0);
                }
                else
                {
                    // Broadcast
                    char out[BUFFER_SIZE];
                    snprintf(out, sizeof(out), "%s: %s", client->name, buffer);
                    broadcast_message(out, client->socket);
                }
            }
        }
    }

    // Cleanup after client disconnect
    if (client->authenticated)
    {
        // Notify others
        char leave_msg[BUFFER_SIZE];
        snprintf(leave_msg, sizeof(leave_msg), "%s has left the chat.\n", client->name);
        broadcast_message(leave_msg, client->socket);

        remove_logged_in_user(client->name);
    }

    // Remove from clients[]
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (clients[i] == client)
        {
            clients[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    // Close if still open
    if (client->socket != -1)
    {
        close(client->socket);
    }
    free(client);
    pthread_detach(pthread_self());
    return NULL;
}

// ============= COMMAND HANDLER =============
void handle_command(client_t *client, const char *commandLine)
{
    char response[BUFFER_SIZE];

    // 1) Tokenize
    char copy[BUFFER_SIZE];
    strncpy(copy, commandLine, sizeof(copy)-1);
    copy[sizeof(copy)-1] = '\0';

    char *tokens[10];
    int numTokens = 0;
    {
        // Simple tokenizer
        char *ptr = strtok(copy, " \t\r\n");
        while (ptr && numTokens < 10) {
            tokens[numTokens++] = ptr;
            ptr = strtok(NULL, " \t\r\n");
        }
    }

    if (numTokens == 0) {
        // Just a slash or blank
        return;
    }

    const char *cmd = tokens[0]; // e.g. "/kick"

    // If not authenticated, only allow certain commands
    if (!client->authenticated) {
        if (strcmp(cmd, "/login") != 0 &&
            strcmp(cmd, "/register") != 0 &&
            strcmp(cmd, "/help") != 0 &&
            strcmp(cmd, "/leave") != 0)
        {
            snprintf(response, sizeof(response), 
                     "You must be logged in to use this command.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
    }

    // ================== /register ===================
    if (strcmp(cmd, "/register") == 0) {
        if (client->authenticated) {
            snprintf(response, sizeof(response),
                     "You are already logged in as '%s'.\n", client->name);
            send(client->socket, response, strlen(response), 0);
            return;
        }
        if (numTokens < 3) {
            snprintf(response, sizeof(response),
                     "Usage: /register <username> <password>\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        const char *username = tokens[1];
        const char *password = tokens[2];

        int ret = register_user(username, password);
        if (ret == 1) {
            strncpy(client->name, username, NAME_LEN - 1);
            client->name[NAME_LEN - 1] = '\0';
            client->authenticated = 1;
            client->is_admin = is_user_admin(username);
            add_logged_in_user(username);

            snprintf(response, sizeof(response),
                     "Registration successful!\n");
            send(client->socket, response, strlen(response), 0);
        }
        else if (ret == 0) {
            snprintf(response, sizeof(response),
                     "User already exists.\n");
            send(client->socket, response, strlen(response), 0);
        }
        else {
            snprintf(response, sizeof(response),
                     "Registration failed.\n");
            send(client->socket, response, strlen(response), 0);
        }
    }
    // ================== /login ===================
    else if (strcmp(cmd, "/login") == 0) {
        if (client->authenticated) {
            snprintf(response, sizeof(response),
                     "Already logged in as '%s'.\n", client->name);
            send(client->socket, response, strlen(response), 0);
            return;
        }
        if (numTokens < 3) {
            snprintf(response, sizeof(response),
                     "Usage: /login <username> <password>\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        const char *username = tokens[1];
        const char *password = tokens[2];
        
        if (is_user_banned(username)) {
            snprintf(response, sizeof(response),
                     "Login denied. You are banned.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        if (is_user_logged_in(username)) {
            snprintf(response, sizeof(response),
                     "User '%s' is already logged in.\n", username);
            send(client->socket, response, strlen(response), 0);
            return;
        }
        if (authenticate_user(username, password)) {
            strncpy(client->name, username, NAME_LEN - 1);
            client->name[NAME_LEN - 1] = '\0';
            client->authenticated = 1;
            client->is_admin = is_user_admin(username);
            client->muted = is_user_muted(username);

            load_ignores_for_user(client);
            add_logged_in_user(username);

            snprintf(response, sizeof(response),
                     "Login successful!\n");
            send(client->socket, response, strlen(response), 0);

            char join_msg[BUFFER_SIZE];
            snprintf(join_msg, sizeof(join_msg),
                     "%s has joined the chat.\n", client->name);
            broadcast_message(join_msg, client->socket);
        }
        else {
            snprintf(response, sizeof(response),
                     "Invalid username or password.\n");
            send(client->socket, response, strlen(response), 0);
        }
    }
    // ================== /leave ===================
    else if (strcmp(cmd, "/leave") == 0) {
        snprintf(response, sizeof(response),
                 "You have left the chat room. Goodbye!\n");
        send(client->socket, response, strlen(response), 0);

        // Force thread loop to exit
        shutdown(client->socket, SHUT_RDWR);
        close(client->socket);
        client->socket = -1;
    }
    // ================== /pm ===================
    else if (strcmp(cmd, "/pm") == 0) {
        if (numTokens < 3) {
            snprintf(response, sizeof(response),
                     "Usage: /pm <username> <message>\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        const char *recipient = tokens[1];

        // Rebuild the rest of tokens as message
        char message[MAX_MESSAGE_LENGTH + 1];
        message[0] = '\0';
        // tokens[2..numTokens-1]
        for (int i = 2; i < numTokens; i++) {
            strncat(message, tokens[i], sizeof(message) - 1 - strlen(message));
            if (i < numTokens-1) {
                strncat(message, " ", sizeof(message) - 1 - strlen(message));
            }
        }

        if (strcmp(client->name, recipient) == 0) {
            snprintf(response, sizeof(response),
                     "You cannot send a private message to yourself.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        client_t *rcpt_client = find_client_by_name(recipient);
        if (!rcpt_client) {
            snprintf(response, sizeof(response),
                     "User '%s' is not logged in.\n", recipient);
            send(client->socket, response, strlen(response), 0);
            return;
        }

        // Check if rcpt_client is ignoring the sender
        int senderIndex = -1;
        for (int i=0; i<MAX_USERS_IN_ROOM; i++){
            if (strcmp(logged_in_users[i], client->name) == 0) {
                senderIndex = i;
                break;
            }
        }
        if (senderIndex >= 0 && rcpt_client->ignores[senderIndex] == 1) {
            // recipient is ignoring the sender
            snprintf(response, sizeof(response),
                     "Message not delivered. %s is ignoring you.\n", recipient);
            send(client->socket, response, strlen(response), 0);
            return;
        }

        // Otherwise deliver
        char private_message[BUFFER_SIZE];
        snprintf(private_message, sizeof(private_message),
                 "[Private] %s: %s\n", client->name, message);
        send(rcpt_client->socket, private_message, strlen(private_message), 0);
        snprintf(response, sizeof(response),
                 "Message sent to %s.\n", recipient);
        send(client->socket, response, strlen(response), 0);
    }
    // ================== /help ===================
    else if (strcmp(cmd, "/help") == 0) {
        snprintf(response, sizeof(response),
                 "Available commands:\n"
                 "/register <user> <pass> - Register a new user\n"
                 "/login <user> <pass>    - Login\n"
                 "/leave                  - Leave chat\n"
                 "/users                  - Show who is online\n"
                 "/pm <user> <msg>        - Private message\n"
                 "/ignore <user>          - Ignore someone's messages\n"
                 "/unignore <user>        - Stop ignoring that user\n"
                 "/mute <user>            - Mute a user (admin)\n"
                 "/unmute <user>          - Unmute a user (admin)\n"
                 "/ban <user>             - Ban a user (admin)\n"
                 "/unban <user>           - Unban a user (admin)\n"
                 "/ban-list               - Show banned users (admin)\n"
                 "/kick <user>            - Kick a user (admin)\n"
                 "/promote <user>         - Promote a user to admin\n"
                 "/demote <user>          - Demote an admin\n"
                 "/status [user]          - Show your or another user's status\n");
        send(client->socket, response, strlen(response), 0);
    }
    // ================== /users ===================
    else if (strcmp(cmd, "/users") == 0) {
        snprintf(response, sizeof(response), "Users in the room:\n");
        for (int i = 0; i < MAX_USERS_IN_ROOM; i++) {
            if (logged_in_users[i][0] != '\0') {
                strncat(response, logged_in_users[i],
                        sizeof(response) - strlen(response) - 1);
                strncat(response, "\n",
                        sizeof(response) - strlen(response) - 1);
            }
        }
        send(client->socket, response, strlen(response), 0);
    }
    // ================== /ignore ===================
    else if (strcmp(cmd, "/ignore") == 0) {
        if (numTokens < 2) {
            snprintf(response, sizeof(response),
                     "Usage: /ignore <username>\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        const char *target = tokens[1];
        if (strcmp(target, client->name) == 0) {
            snprintf(response, sizeof(response),
                     "You cannot ignore yourself.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        // Find index of target
        int targetIndex = -1;
        for (int i=0; i<MAX_USERS_IN_ROOM; i++){
            if (strcmp(logged_in_users[i], target) == 0) {
                targetIndex = i;
                break;
            }
        }
        if (targetIndex == -1) {
            snprintf(response, sizeof(response),
                     "User '%s' is not logged in.\n", target);
        } else {
            client->ignores[targetIndex] = 1;
            add_ignore_in_file(client->name, target);
            snprintf(response, sizeof(response),
                     "You are now ignoring '%s'.\n", target);
        }
        send(client->socket, response, strlen(response), 0);
    }
    // ================== /unignore ===================
    else if (strcmp(cmd, "/unignore") == 0) {
        if (numTokens < 2) {
            snprintf(response, sizeof(response),
                     "Usage: /unignore <username>\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        const char *target = tokens[1];
        int targetIndex = -1;
        for (int i=0; i<MAX_USERS_IN_ROOM; i++){
            if (strcmp(logged_in_users[i], target) == 0) {
                targetIndex = i;
                break;
            }
        }
        if (targetIndex == -1) {
            snprintf(response, sizeof(response),
                     "User '%s' is not logged in.\n", target);
        } else {
            client->ignores[targetIndex] = 0;
            remove_ignore_in_file(client->name, target);
            snprintf(response, sizeof(response),
                     "You no longer ignore '%s'.\n", target);
        }
        send(client->socket, response, strlen(response), 0);
    }
    // ================== /mute ===================
    else if (strcmp(cmd, "/mute") == 0) {
        if (!client->is_admin) {
            snprintf(response, sizeof(response),
                     "You do not have permission.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        if (numTokens < 2) {
            snprintf(response, sizeof(response),
                     "Usage: /mute <username>\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        const char *target = tokens[1];
        if (strcmp(client->name, target) == 0) {
            snprintf(response, sizeof(response),
                     "You cannot mute yourself.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        client_t *tc = find_client_by_name(target);
        if (!tc) {
            snprintf(response, sizeof(response),
                     "User '%s' is not logged in.\n", target);
            send(client->socket, response, strlen(response), 0);
            return;
        }
        // Mute them
        if (tc->muted) {
            snprintf(response, sizeof(response),
                     "User '%s' is already muted.\n", target);
            send(client->socket, response, strlen(response), 0);
            return;
        }
        tc->muted = 1;
        mute_user(target);
        snprintf(response, sizeof(response),
                 "User '%s' has been muted.\n", target);
        send(client->socket, response, strlen(response), 0);

        snprintf(response, sizeof(response),
                 "You have been muted by '%s'.\n", client->name);
        send(tc->socket, response, strlen(response), 0);
    }
    // ================== /unmute ===================
    else if (strcmp(cmd, "/unmute") == 0) {
        if (!client->is_admin) {
            snprintf(response, sizeof(response),
                     "You do not have permission.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        if (numTokens < 2) {
            snprintf(response, sizeof(response),
                     "Usage: /unmute <username>\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        const char *target = tokens[1];
        client_t *tc = find_client_by_name(target);
        if (!tc) {
            snprintf(response, sizeof(response),
                     "User '%s' not found or not logged.\n", target);
            send(client->socket, response, strlen(response), 0);
            return;
        }
        if (!tc->muted) {
            snprintf(response, sizeof(response),
                     "User '%s' is not muted.\n", target);
            send(client->socket, response, strlen(response), 0);
            return;
        }
        tc->muted = 0;
        unmute_user(target);
        snprintf(response, sizeof(response),
                 "User '%s' has been unmuted.\n", target);
        send(client->socket, response, strlen(response), 0);

        snprintf(response, sizeof(response),
                 "You have been unmuted by '%s'.\n", client->name);
        send(tc->socket, response, strlen(response), 0);
    }
    // ================== /ban ===================
    else if (strcmp(cmd, "/ban") == 0) {
        if (!client->is_admin) {
            snprintf(response, sizeof(response),
                     "You do not have permission.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        if (numTokens < 2) {
            snprintf(response, sizeof(response),
                     "Usage: /ban <username>\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        const char *target = tokens[1];
        if (strcmp(client->name, target) == 0) {
            snprintf(response, sizeof(response),
                     "You cannot ban yourself.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        // Check if user already banned
        if (is_user_banned(target)) {
            snprintf(response, sizeof(response),
                     "User '%s' is already banned.\n", target);
            send(client->socket, response, strlen(response), 0);
            return;
        }
        // Check if user even exists or is logged in
        client_t *tc = find_client_by_name(target);
        if (tc) {
            // Kick them immediately
            snprintf(response, sizeof(response),
                     "You have been banned by '%s'.\n", client->name);
            send(tc->socket, response, strlen(response), 0);

            char ban_msg[BUFFER_SIZE];
            snprintf(ban_msg, sizeof(ban_msg),
                     "%s has been banned by %s.\n", target, client->name);
            broadcast_message(ban_msg, tc->socket);

            shutdown(tc->socket, SHUT_RDWR);
            close(tc->socket);
            tc->socket = -1;
        }
        // Write to ban file
        ban_user(target);
        snprintf(response, sizeof(response),
                 "User '%s' is now banned.\n", target);
        send(client->socket, response, strlen(response), 0);
    }
    // ================== /unban ===================
    else if (strcmp(cmd, "/unban") == 0) {
        if (!client->is_admin) {
            snprintf(response, sizeof(response),
                     "You do not have permission.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        if (numTokens < 2) {
            snprintf(response, sizeof(response),
                     "Usage: /unban <username>\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        const char *target = tokens[1];
        // Check if user is actually banned
        if (!is_user_banned(target)) {
            snprintf(response, sizeof(response),
                     "User '%s' is not currently banned.\n", target);
            send(client->socket, response, strlen(response), 0);
            return;
        }
        unban_user(target);
        snprintf(response, sizeof(response),
                 "User '%s' has been unbanned.\n", target);
        send(client->socket, response, strlen(response), 0);
    }
    // ================== /ban-list ===================
    else if (strcmp(cmd, "/ban-list") == 0) {
        if (!client->is_admin) {
            snprintf(response, sizeof(response),
                     "You do not have permission.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        // Read the banned file
        FILE *f = fopen(BANNED_FILE, "r");
        if (!f) {
            snprintf(response, sizeof(response),
                     "No banned users.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        char line[NAME_LEN];
        snprintf(response, sizeof(response), "Banned users:\n");
        int foundAny = 0;
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\n")] = '\0';
            if (line[0] != '\0') {
                foundAny = 1;
                strncat(response, line,
                        sizeof(response) - 1 - strlen(response));
                strncat(response, "\n",
                        sizeof(response) - 1 - strlen(response));
            }
        }
        fclose(f);
        if (!foundAny) {
            strncat(response, "(none)\n", sizeof(response) - 1 - strlen(response));
        }
        send(client->socket, response, strlen(response), 0);
    }
    // ================== /kick ===================
    else if (strcmp(cmd, "/kick") == 0) {
        if (!client->is_admin) {
            snprintf(response, sizeof(response),
                     "You do not have permission.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        if (numTokens < 2) {
            snprintf(response, sizeof(response),
                     "Usage: /kick <username>\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        const char *target = tokens[1];
        if (strcmp(client->name, target) == 0) {
            snprintf(response, sizeof(response),
                     "You cannot kick yourself.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        client_t *tc = find_client_by_name(target);
        if (!tc) {
            snprintf(response, sizeof(response),
                     "User '%s' is not logged in.\n", target);
            send(client->socket, response, strlen(response), 0);
            return;
        }
        // Kick them
        // Send to that user only
        snprintf(response, sizeof(response),
                 "You have been kicked by '%s'.\n", client->name);
        send(tc->socket, response, strlen(response), 0);

        // Now broadcast to others: "<target> was kicked by <admin>."
        char msg[BUFFER_SIZE];
        snprintf(msg, sizeof(msg),
                 "%s was kicked by %s.\n", target, client->name);
        broadcast_message(msg, tc->socket);

        shutdown(tc->socket, SHUT_RDWR);
        close(tc->socket);
        tc->socket = -1;

        // Confirm to admin
        snprintf(response, sizeof(response),
                 "User '%s' has been kicked.\n", target);
        send(client->socket, response, strlen(response), 0);
    }
    // ================== /promote ===================
    else if (strcmp(cmd, "/promote") == 0) {
        if (!client->is_admin) {
            snprintf(response, sizeof(response),
                     "You do not have permission.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        if (numTokens < 2) {
            snprintf(response, sizeof(response),
                     "Usage: /promote <username>\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        const char *target = tokens[1];
        if (strcmp(client->name, target) == 0) {
            snprintf(response, sizeof(response),
                     "You are already admin.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        client_t *tc = find_client_by_name(target);
        if (!tc) {
            snprintf(response, sizeof(response),
                     "User '%s' not found.\n", target);
            send(client->socket, response, strlen(response), 0);
            return;
        }
        if (tc->is_admin) {
            snprintf(response, sizeof(response),
                     "User '%s' is already admin.\n", target);
            send(client->socket, response, strlen(response), 0);
            return;
        }
        promote_user(tc);
        add_admin_to_file(target);
        snprintf(response, sizeof(response),
                 "User '%s' promoted to admin.\n", target);
        send(client->socket, response, strlen(response), 0);

        snprintf(response, sizeof(response),
                 "You have been promoted by '%s'.\n", client->name);
        send(tc->socket, response, strlen(response), 0);
    }
    // ================== /demote ===================
    else if (strcmp(cmd, "/demote") == 0) {
        if (!client->is_admin) {
            snprintf(response, sizeof(response),
                     "You do not have permission.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        if (numTokens < 2) {
            snprintf(response, sizeof(response),
                     "Usage: /demote <username>\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        const char *target = tokens[1];
        if (strcmp(client->name, target) == 0) {
            snprintf(response, sizeof(response),
                     "You cannot demote yourself.\n");
            send(client->socket, response, strlen(response), 0);
            return;
        }
        client_t *tc = find_client_by_name(target);
        if (!tc) {
            snprintf(response, sizeof(response),
                     "User '%s' not found.\n", target);
            send(client->socket, response, strlen(response), 0);
            return;
        }
        if (!tc->is_admin) {
            snprintf(response, sizeof(response),
                     "User '%s' is not admin.\n", target);
            send(client->socket, response, strlen(response), 0);
            return;
        }
        demote_user(tc);
        remove_admin_from_file(target);
        snprintf(response, sizeof(response),
                 "User '%s' demoted.\n", target);
        send(client->socket, response, strlen(response), 0);

        snprintf(response, sizeof(response),
                 "You have been demoted by '%s'.\n", client->name);
        send(tc->socket, response, strlen(response), 0);
    }
    // ================== /status ===================
    else if (strcmp(cmd, "/status") == 0) {
        // If /status <user> => show <user> status
        // else show your own
        if (numTokens == 1) {
            // Show own status
            snprintf(response, sizeof(response),
                     "Name: %s\nAdmin: %s\nMuted: %s\n",
                     client->name,
                     client->is_admin ? "Yes" : "No",
                     client->muted     ? "Yes" : "No");
            send(client->socket, response, strlen(response), 0);
        } else {
            const char *target = tokens[1];
            client_t *tc = find_client_by_name(target);
            if (!tc) {
                snprintf(response, sizeof(response),
                         "User '%s' is not logged in.\n", target);
            } else {
                snprintf(response, sizeof(response),
                         "Name: %s\nAdmin: %s\nMuted: %s\n",
                         tc->name,
                         tc->is_admin ? "Yes" : "No",
                         tc->muted     ? "Yes" : "No");
            }
            send(client->socket, response, strlen(response), 0);
        }
    }
    // ================== Unknown ===================
    else {
        snprintf(response, sizeof(response),
                 "Unknown command: %s\n", cmd);
        send(client->socket, response, strlen(response), 0);
    }
}
// ======================= FILE-BASED BAN / MUTE =======================

// Check BANNED_FILE for a line with `username`
int is_user_banned(const char *username)
{
    FILE *f = fopen(BANNED_FILE, "r");
    if (!f)
        return 0;
    char line[NAME_LEN];
    while (fgets(line, sizeof(line), f))
    {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, username) == 0)
        {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}
void ban_user(const char *username)
{
    // Append
    FILE *f = fopen(BANNED_FILE, "a");
    if (!f)
        return;
    fprintf(f, "%s\n", username);
    fclose(f);
}
void unban_user(const char *username)
{
    // Read all lines except target
    FILE *f = fopen(BANNED_FILE, "r");
    if (!f)
        return;
    char tmp[] = "tmp_ban.txt";
    FILE *out = fopen(tmp, "w");
    if (!out)
    {
        fclose(f);
        return;
    }
    char line[NAME_LEN];
    while (fgets(line, sizeof(line), f))
    {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, username) != 0)
        {
            fprintf(out, "%s\n", line);
        }
    }
    fclose(f);
    fclose(out);
    remove(BANNED_FILE);
    rename(tmp, BANNED_FILE);
}

// MUTE
int is_user_muted(const char *username)
{
    FILE *f = fopen(MUTED_FILE, "r");
    if (!f)
        return 0;
    char line[NAME_LEN];
    while (fgets(line, sizeof(line), f))
    {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, username) == 0)
        {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}
void mute_user(const char *username)
{
    FILE *f = fopen(MUTED_FILE, "a");
    if (!f)
        return;
    fprintf(f, "%s\n", username);
    fclose(f);
}
void unmute_user(const char *username)
{
    FILE *f = fopen(MUTED_FILE, "r");
    if (!f)
        return;
    char tmp[] = "tmp_muted.txt";
    FILE *out = fopen(tmp, "w");
    if (!out)
    {
        fclose(f);
        return;
    }
    char line[NAME_LEN];
    while (fgets(line, sizeof(line), f))
    {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, username) != 0)
        {
            fprintf(out, "%s\n", line);
        }
    }
    fclose(f);
    fclose(out);
    remove(MUTED_FILE);
    rename(tmp, MUTED_FILE);
}

// ======================= FILE-BASED IGNORES =======================
// Format: userA: userX,userY,userZ
// We parse each line for the left side user, then parse the right side as a comma list

void load_ignores_for_user(client_t *client)
{
    FILE *f = fopen(IGNORES_FILE, "r");
    if (!f)
        return;
    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), f))
    {
        line[strcspn(line, "\n")] = '\0';
        // parse "Alice: Bob,Mark,John"
        char *colon = strchr(line, ':');
        if (!colon)
            continue;
        *colon = '\0'; // split
        char *ignorer = line;
        char *ignoredList = colon + 1;
        // Trim spaces if needed
        while (*ignoredList == ' ')
            ignoredList++;

        if (strcmp(ignorer, client->name) == 0)
        {
            // This line is about our client
            // parse comma separated
            char *token = strtok(ignoredList, ",");
            while (token)
            {
                // For each ignored user, find index in logged_in_users
                // so we can set client->ignores[index] = 1
                // but user might not be logged in yet, so we only do if found
                for (int i = 0; i < MAX_USERS_IN_ROOM; i++)
                {
                    if (strcmp(logged_in_users[i], token) == 0)
                    {
                        client->ignores[i] = 1;
                        break;
                    }
                }
                token = strtok(NULL, ",");
            }
            break;
        }
    }
    fclose(f);
}

// Helper to rewrite entire ignores file for a single user
// We read old lines, replace the line for "ignorer"
static void rewrite_ignores_for_user(const char *ignorer, const char *new_line)
{
    FILE *f = fopen(IGNORES_FILE, "r");
    char tmpfile[] = "ignores_tmp.txt";
    FILE *out = fopen(tmpfile, "w");
    if (!out)
    {
        if (f)
            fclose(f);
        return;
    }
    if (f)
    {
        char line[BUFFER_SIZE];
        int replaced = 0;
        while (fgets(line, sizeof(line), f))
        {
            char copy[BUFFER_SIZE];
            strcpy(copy, line);
            copy[strcspn(copy, "\n")] = '\0';
            char *colon = strchr(copy, ':');
            if (!colon)
            {
                // just copy it forward
                fprintf(out, "%s", line);
                continue;
            }
            *colon = '\0';
            if (strcmp(copy, ignorer) == 0)
            {
                // skip old line, write new line
                if (new_line)
                {
                    fprintf(out, "%s\n", new_line);
                }
                replaced = 1;
            }
            else
            {
                // copy old line
                fprintf(out, "%s", line);
            }
        }
        fclose(f);
        // if not replaced (brand new user ignoring someone)
        if (!replaced && new_line)
        {
            fprintf(out, "%s\n", new_line);
        }
    }
    else
    {
        // No file existed? Just write new_line
        if (new_line)
        {
            fprintf(out, "%s\n", new_line);
        }
    }
    fclose(out);
    remove(IGNORES_FILE);
    rename(tmpfile, IGNORES_FILE);
}

void add_ignore_in_file(const char *ignorer, const char *ignoree)
{
    char currentIgnores[BUFFER_SIZE];
    currentIgnores[0] = '\0';

    FILE *f = fopen(IGNORES_FILE, "r");
    if (f)
    {
        char line[BUFFER_SIZE];
        while (fgets(line, sizeof(line), f))
        {
            line[strcspn(line, "\n")] = '\0';
            char *colon = strchr(line, ':');
            if (!colon)
                continue;
            *colon = '\0';
            char *left = line;
            char *right = colon + 1;
            while (*right == ' ')
                right++;
            if (strcmp(left, ignorer) == 0)
            {
                // store it
                strncpy(currentIgnores, right, sizeof(currentIgnores) - 1);
                currentIgnores[sizeof(currentIgnores) - 1] = '\0';
                break;
            }
        }
        fclose(f);
    }
    // currentIgnores now might be "Bob,Mark" etc.
    // We only add ignoree if not already present
    if (strstr(currentIgnores, ignoree) == NULL)
    {
        if (currentIgnores[0] != '\0')
        {
            // append comma first
            strncat(currentIgnores, ",", sizeof(currentIgnores) - 1 - strlen(currentIgnores));
        }
        strncat(currentIgnores, ignoree, sizeof(currentIgnores) - 1 - strlen(currentIgnores));
    }
    // Build new line "ignorer: <currentIgnores>"
    char new_line[BUFFER_SIZE];
    snprintf(new_line, sizeof(new_line), "%s: %s", ignorer, currentIgnores);
    rewrite_ignores_for_user(ignorer, new_line);
}

void remove_ignore_in_file(const char *ignorer, const char *ignoree)
{
    // Similar logic to add_ignore_in_file, remove 'ignoree' from comma list
    char currentIgnores[BUFFER_SIZE];
    currentIgnores[0] = '\0';

    FILE *f = fopen(IGNORES_FILE, "r");
    if (f)
    {
        char line[BUFFER_SIZE];
        while (fgets(line, sizeof(line), f))
        {
            line[strcspn(line, "\n")] = '\0';
            char *colon = strchr(line, ':');
            if (!colon)
                continue;
            *colon = '\0';
            char *left = line;
            char *right = colon + 1;
            while (*right == ' ')
                right++;
            if (strcmp(left, ignorer) == 0)
            {
                strncpy(currentIgnores, right, sizeof(currentIgnores) - 1);
                currentIgnores[sizeof(currentIgnores) - 1] = '\0';
                break;
            }
        }
        fclose(f);
    }
    // now remove ignoree from currentIgnores
    // We'll tokenize by ',' and rebuild
    char *tokens[100];
    int count = 0;
    char temp[BUFFER_SIZE];
    strncpy(temp, currentIgnores, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';

    char *token = strtok(temp, ",");
    while (token && count < 100)
    {
        tokens[count++] = token;
        token = strtok(NULL, ",");
    }
    // Rebuild without 'ignoree'
    char new_list[BUFFER_SIZE];
    new_list[0] = '\0';
    for (int i = 0; i < count; i++)
    {
        if (strcmp(tokens[i], ignoree) != 0)
        {
            if (new_list[0] != '\0')
            {
                strncat(new_list, ",", sizeof(new_list) - 1 - strlen(new_list));
            }
            strncat(new_list, tokens[i], sizeof(new_list) - 1 - strlen(new_list));
        }
    }

    if (new_list[0] == '\0')
    {
        // means no more ignores
        rewrite_ignores_for_user(ignorer, NULL); // remove line entirely
    }
    else
    {
        char new_line[BUFFER_SIZE];
        snprintf(new_line, sizeof(new_line), "%s: %s", ignorer, new_list);
        rewrite_ignores_for_user(ignorer, new_line);
    }
}