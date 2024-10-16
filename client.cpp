#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstdlib>
#include <vector>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

using namespace std;

int sock;

// Fixed IV (16 bytes)
const std::vector<unsigned char> FIXED_IV = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

// AES CBC encryption function
std::vector<unsigned char> aesEncrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int outlen, finallen;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), FIXED_IV.data());

    EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size());
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &finallen);

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(outlen + finallen);
    return ciphertext;
}

// Pad the Diffie-Hellman key to a 16-byte AES key
std::vector<unsigned char> padKey(int small_key) {
    std::vector<unsigned char> key(16, 0);
    key[0] = static_cast<unsigned char>(small_key);
    return key;
}

// Convert a string to a vector of unsigned char
std::vector<unsigned char> stringToVector(const std::string& str) {
    return std::vector<unsigned char>(str.begin(), str.end());
}

// Send encrypted request and get response
string send_encrypted_request(const string& request, const vector<unsigned char>& key) {
    std::vector<unsigned char> encrypted_request = aesEncrypt(stringToVector(request), key);

    if (send(sock, encrypted_request.data(), encrypted_request.size(), 0) < 0) {
        return "";
    }

    char buf[256];
    memset(buf, 0, sizeof(buf));
    recv(sock, buf, sizeof(buf), 0);

    return string(buf);  // Return the server's full response
}

// Function to apply ROT13 encryption/decryption
string applyROT13(const string& input) {
    string result = input;
    for (char &c : result) {
        if (isalpha(c)) {
            if (isupper(c)) {
                c = 'A' + (c - 'A' + 13) % 26;
            } else {
                c = 'a' + (c - 'a' + 13) % 26;
            }
        }
    }
    return result;
}

// Registration function
void register_user(const vector<unsigned char>& key) {
    string username, email, password;

    // Validate email with the server
    while (true) {
        cout << "Enter your email (must end with @gmail.com): ";
        getline(cin, email);

        string response = send_encrypted_request("validate_email:" + email, key);
        if (response == "Valid") {
            cout << "Valid email.\n";
            break;
        } else {
            cout << "Invalid email format. Try again.\n";  // Show server's response
        }
    }

    // Validate password with the server
    while (true) {
        cout << "Enter your password (minimum 4 characters, one special character): ";
        getline(cin, password);

        string response = send_encrypted_request("validate_password:" + password, key);
        if (response == "Valid") {
            cout << "Valid password.\n";
            break;
        } else {
            cout << "Invalid password format. Try again.\n";
        }
    }

    // Check username availability
    while (true) {
        cout << "Enter your username: ";
        getline(cin, username);

        string response = send_encrypted_request("username_exists:" + username, key);
        if (response == "Valid") {
            cout << "Username available.\n";
            break;
        } else {
            cout << "Username already exists. Try again.\n";
        }
    }

    // Complete registration
    string registration_details = "register:" + username + "," + email + "," + password;
    string response = send_encrypted_request(registration_details, key);
    if (response == "Valid") {
        cout << "Registration successful!\n";
    } else {
        cout << "Registration failed. Try again.\n";
    }
}

// Login function
bool login_user(const vector<unsigned char>& key) {
    string username, password;

    cout << "Enter your username: ";
    getline(cin, username);

    cout << "Enter your password: ";
    getline(cin, password);

    string login_details = "login:" + username + "," + password;
    string response = send_encrypted_request(login_details, key);

    if (response == "Valid") {
        char buf[256];
        char message[256];

        while (true) {
            // Send message to server
            cout << "You (Client): ";
            string client_message;
            getline(cin, client_message);
            strcpy(message, applyROT13(client_message).c_str());
            send(sock, message, sizeof(message), 0);

            // If the client sends "exit", terminate the chat
            if (strcmp(message, "rkvg") == 0) {
                break;
            }
             if (strcmp(message, "olr") == 0) {
                break;
            }

            // Receive message from server
            memset(buf, 0, sizeof(buf));
            recv(sock, buf, sizeof(buf), 0);
            cout << "Server: " << applyROT13(buf) << endl;
        }
        return true;
    } else {
        cout << "Login failed. Reason: " << response << "\n";  // Print reason for failure
        return false;
    }
}

// Password reset function (on the client side)
void reset_password(const vector<unsigned char>& key) {
    string username, email, new_password;

    cout << "Enter your username: ";
    getline(cin, username);

    cout << "Enter your registered email: ";
    getline(cin, email);

    // Send reset password request
    string response = send_encrypted_request("reset_password:" + username + "," + email, key);
    if (response == "Valid") {
        cout << "Account verified! Enter a new password: ";
        getline(cin, new_password);

        // Send request to update the password
        string reset_details = "update_password:" + username + "," + new_password;
        response = send_encrypted_request(reset_details, key);
        if (response == "Valid") {
            cout << "Password updated successfully!\n";
        } else {
            cout << "Failed to update the password. Try again.\n";
        }
    } else {
        cout << "Username and email do not match. Reason: " << response << "\n";
    }
}



// Modular exponentiation function
int mod_exp(int base, int exp, int mod) {
    int result = 1;
    base = base % mod;

    while (exp > 0) {
        if (exp % 2 == 1) result = (result * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }

    return result;
}

// Diffie-Hellman key exchange
int diffie_hellman_client(int sock) {
    int p = 23, g = 5, a = 6;
    int partial_key_client = mod_exp(g, a, p);

    send(sock, &partial_key_client, sizeof(partial_key_client), 0);

    int partial_key_server;
    recv(sock, &partial_key_server, sizeof(partial_key_server), 0);

    return mod_exp(partial_key_server, a, p);
}

// Create and connect socket
void create_socket() {
    sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(8080);
    connect(sock, (struct sockaddr *)&server_address, sizeof(server_address));
}

// Function to choose between login, register, or reset password
void user_action(const vector<unsigned char>& aes_key) {
    cout << "Do you want to (1) Register, (2) Login, or (3) Reset Password? ";
    int choice;
    cin >> choice;
    cin.ignore();  // Clear the newline from input buffer

    switch (choice) {
        case 1:
            register_user(aes_key);
            break;
        case 2:
            if (!login_user(aes_key)) {
                cout << "Login failed. Exiting...\n";
            }
            break;
        case 3:
            reset_password(aes_key);
            break;
        default:
            cout << "Invalid choice. Exiting...\n";
            break;
    }
}

int main() {
    create_socket();
    int mutual_key = diffie_hellman_client(sock);

    vector<unsigned char> aes_key = padKey(mutual_key);

    user_action(aes_key);

    close(sock);
    return 0;
}
