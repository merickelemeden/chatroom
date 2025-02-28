# Chatroom App

## 📌 Overview
This is a chatroom application that allows users to communicate in a shared chatroom. Users can register and log in using a username and password to participate in real-time text-based conversations.

## ⚡ Features
- User registration & login
- Real-time messaging in a shared chatroom
- Private messaging between users
- Admin commands (mute, kick, ban, promote, demote)
- User list and status checking

## 🛠 Installation
### **1. Clone the Repository**
```sh
git clone https://github.com/yourusername/chatroom.git
cd chatroom
```
### **2. Compile the Server & Client**
```sh
gcc server.c -o server
gcc client.c -o client
```

## 🚀 Running the Application
### **Start the Server**
```sh
./server # Uses default port 8080
./server 8888 # Custom port
```

### **Start the Client**
```sh
./client # Connects to localhost on default port 8080
./client 8888 # Connects to localhost on custom port
./client 192.168.x.x 8080 # Connects to a remote server
```

## 💬 Usage
### **Basic Commands**
```sh
/register <username> <password>  # Register a new account
/login <username> <password>     # Log in to the chatroom
/leave                           # Log out and disconnect
/users                           # View online users
/pm <username> <message>         # Send a private message
/ignore <username>               # Ignore messages from a user
/unignore <username>             # Stop ignoring a user
```
### **Admin Commands**
```sh
/kick <username>    # Remove a user from the chat
/ban <username>     # Ban a user from logging in
/unban <username>   # Unban a previously banned user
/mute <username>    # Mute a user from sending messages
/unmute <username>  # Unmute a user
/promote <username> # Grant admin privileges
/demote <username>  # Revoke admin privileges
```

## 📄 Documentation
For a detailed guide on how to use the application, see the [User Guide](docs/USAGE.md).

## 📜 License
This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

