# Secure-client-server-model-
# Client-Server Chat Application

## Table of Contents
- [Introduction](#introduction)
- [Technologies Used](#technologies-used)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Encryption Mechanism](#encryption-mechanism)
- [Conclusion](#conclusion)

## Introduction
This client-server chat application enables secure communication between users through a registration and login system. The application employs advanced cryptographic techniques to ensure that sensitive data is transmitted securely.

## Technologies Used
- **Programming Language**: C++
- **Libraries**: 
  - OpenSSL for encryption
  - Regex for email validation
- **Development Environment**: Kali Linux

## Features
- **User Registration**: Users can create an account with unique usernames and passwords. Passwords are hashed using SHA-256 for security.
- **User Login**: Authentication is performed securely, ensuring user credentials are validated before granting access.
- **Secure Communication**: Messages are encrypted using the ROT13 encryption method after the initial setup of a secure key using the Diffie-Hellman key exchange.
- **Data Protection**: Sensitive information (username, email, password) is transmitted over the network using AES in CBC mode with a 128-bit key.
- **Real-time Chat**: Users can send and receive messages in real-time, with both client and server able to communicate seamlessly.

## Installation
To install and run the application, follow these steps:

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. Compile the client and server files:
   ```bash
   g++ -o server server.cpp -lssl -lcrypto
   g++ -o client client.cpp -lssl -lcrypto
   ```

3. Run the server in one terminal:
   ```bash
   ./server
   ```

4. Run the client in another terminal:
   ```bash
   ./client
   ```

## Usage
- **Register**: Follow the prompts to register a new account.
- **Login**: Enter your username and password to log in.
- **Chat**: Once logged in, you can start sending messages to the server and receive responses.

## Encryption Mechanism
The application utilizes multiple encryption techniques to ensure data security:

- **SHA-256**: Used for hashing user passwords during registration and login.
- **AES (CBC mode)**: Applied for encrypting sensitive user data sent between client and server.
- **ROT13**: Employed for encrypting chat messages after the initial login, adding an extra layer of security.

## Conclusion
This client-server chat application demonstrates the implementation of secure communication protocols and cryptographic techniques. The use of AES encryption, SHA-256 hashing, and ROT13 encryption ensures that user data is protected against unauthorized access. Through this project, we showcase the significance of cybersecurity in modern applications.

## Author
- Muhammad  Akash waris
