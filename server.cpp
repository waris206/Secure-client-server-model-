#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstdlib>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vector>
#include <regex>
using namespace std;

int client_socket;
int server_socket;

// Fixed salt
const string SALT = "!12";
// Fixed IV (16 bytes)
const std::vector<unsigned char> FIXED_IV = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};



// AES CBC decryption function
std::vector<unsigned char> aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> plaintext(ciphertext.size() + AES_BLOCK_SIZE);

    int outlen, finallen;


    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), FIXED_IV.data());

    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext.data(), ciphertext.size())) {

        EVP_CIPHER_CTX_free(ctx);

        throw runtime_error("Error during AES decryption (DecryptUpdate).");

    }



    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &finallen)) {

        EVP_CIPHER_CTX_free(ctx);

        throw runtime_error("Error during AES decryption (DecryptFinal).");

    }



    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(outlen + finallen);

    return plaintext;

}



// Pad the Diffie-Hellman key to a 16-byte AES key

std::vector<unsigned char> padKey(int small_key) {

    std::vector<unsigned char> key(16, 0);

    key[0] = static_cast<unsigned char>(small_key);

    return key;

}

// Convert a vector of unsigned char to a string

std::string vectorToString(const std::vector<unsigned char>& vec) {

    return std::string(vec.begin(), vec.end());

}
// Receive encrypted data and decrypt it

std::string receive_and_decrypt_request(int sock, const vector<unsigned char>& key) {

    char buf[1024];

    int bytes_received = recv(sock, buf, sizeof(buf), 0);

    if (bytes_received <= 0) {

        return "";

    }
  std::vector<unsigned char> encrypted_data(buf, buf + bytes_received);

    try {

        std::vector<unsigned char> decrypted_data = aesDecrypt(encrypted_data, key);

        return vectorToString(decrypted_data);

    } catch (const std::exception& e) {

        return "";

    }

}

// Hash password with fixed salt using SHA-256

string hash_password(const string& user_password) {

    string salted_password = user_password + SALT;

    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256(reinterpret_cast<const unsigned char*>(salted_password.c_str()), salted_password.size(), hash);
    string hash_string;

    char temp[3];

    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {

        sprintf(temp, "%02x", hash[i]);

        hash_string += temp;

    }

    return hash_string;

}
// Validate email format

bool validate_email(const string& user_email) {

    const regex pattern(R"((\w+)(\.{1}\w+)*@gmail\.com)");

    return regex_match(user_email, pattern);

}

// Validate password (minimum 4 characters, must contain a special character)

bool validate_password(const string& user_password) {

    if (user_password.length() < 4) return false;

    if (user_password.find_first_of("!@$#%") == string::npos) return false;

    return true;

}
// Check if username exists

bool username_exists(const string& username) {

    ifstream file("users.txt");

    string line;

    while (getline(file, line)) {

        string stored_username = line.substr(0, line.find(','));

        if (stored_username == username) {

            return true;

        }

    }

    return false;

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

// Function to handle chat messages

void start_chat() {

    char buf[256];

    char message[256];
    while (true) {

        memset(buf, 0, sizeof(buf));


        recv(client_socket, buf, sizeof(buf), 0);
        
    



        if (strcmp(buf, "rkvg") == 0) {

            cout << "Client disconnected from the chat.\n";

            break;

        }
     if (strcmp(buf, "olr") == 0) {

            cout << "Client say goodbye from the chat.\n";

            break;

        }
      cout << "Client: " << applyROT13(buf) << endl;

      cout << "You (Server): ";

        string response;

        getline(cin, response);

        strcpy(message, applyROT13(response).c_str());
        send(client_socket, message, sizeof(message), 0);

    }

}

// Handle client requests for login, registration, and password reset

void handle_client_requests(int mutual_key) {

    std::vector<unsigned char> aes_key = padKey(mutual_key);
    while (true) {

        string request = receive_and_decrypt_request(client_socket, aes_key);
       if (request.empty()) {
        break;
       }
        if (request.find("login:") == 0) {

            string login_details = request.substr(6);

            string username = login_details.substr(0, login_details.find(','));

            string plaintext_password = login_details.substr(login_details.find(',') + 1);
            string hashed_password = hash_password(plaintext_password);
           ifstream file("users.txt");

            string line;

            bool user_found = false;
          while (getline(file, line)) {

                string stored_username = line.substr(0, line.find(','));

                string stored_password = line.substr(line.rfind(',') + 1);
               if (stored_username == username && stored_password == hashed_password) {

                    send(client_socket, "Valid", 6, 0);

                    start_chat();  // Start the chat after successful login

                    return;

                }

            }
         send(client_socket, "Invalid username or password.", 31, 0);

        } else if (request.find("reset_password:") == 0) {

    string reset_details = request.substr(14);

    string username = reset_details.substr(0, reset_details.find(','));

    string email = reset_details.substr(reset_details.find(',') + 1);

    // Check if username and email match

    ifstream file("users.txt");

    string line;

    bool user_found = false;

  // Read through the users.txt file to check for matching username and email

    while (getline(file, line)) {

        string stored_username = line.substr(0, line.find(','));

        string stored_email = line.substr(line.find(',') + 1, line.rfind(',') - line.find(',') - 1);

           // Compare both username and email for an exact match

        if (stored_username == username && stored_email == email) {

            send(client_socket, "Valid", 6, 0);  // Send "Valid" if both match

            user_found = true;

            break;

        }

    }
      if (!user_found) {

        send(client_socket, "Invalid", 8, 0);  // Send "Invalid" if no match is found

    }

}

 else if (request.find("update_password:") == 0) {

            string update_details = request.substr(16);

            string username = update_details.substr(0, update_details.find(','));

            string new_password = update_details.substr(update_details.find(',') + 1);



            string hashed_password = hash_password(new_password);
          // Update the password in the file

            ifstream file("users.txt");

            ofstream temp_file("temp.txt");

            string line;
          while (getline(file, line)) {

                string stored_username = line.substr(0, line.find(','));

                if (stored_username == username) {

                    string stored_email = line.substr(line.find(',') + 1, line.rfind(',') - line.find(',') - 1);

                    temp_file << username << "," << stored_email << "," << hashed_password << endl;

                } else {

                    temp_file << line << endl;

                }

            }
          file.close();

            temp_file.close();

            remove("users.txt");

            rename("temp.txt", "users.txt");
          send(client_socket, "Valid", 6, 0);

        } else if (request.find("validate_email:") == 0) {

            string email = request.substr(15);

            if (validate_email(email)) {

                send(client_socket, "Valid", 6, 0);

            } else {

                send(client_socket, "Invalid", 8, 0);

            }

        } else if (request.find("validate_password:") == 0) {

            string password = request.substr(18);

            if (validate_password(password)) {

                send(client_socket, "Valid", 6, 0);

            } else {

                send(client_socket, "Invalid", 8, 0);

            }

        } else if (request.find("username_exists:") == 0) {

            string username = request.substr(16);

            if (username_exists(username)) {

                send(client_socket, "Invalid", 8, 0);

            } else {

                send(client_socket, "Valid", 6, 0);

            }

        } else if (request.find("register:") == 0) {

            string user_details = request.substr(9);

            string username = user_details.substr(0, user_details.find(','));

            string email = user_details.substr(user_details.find(',') + 1, user_details.rfind(',') - user_details.find(',') - 1);

            string password = user_details.substr(user_details.rfind(',') + 1);
          string hashed_password = hash_password(password);
        ofstream file("users.txt", ios::app);

            file << username << "," << email << "," << hashed_password << endl;

            file.close();
         send(client_socket, "Valid", 6, 0);

        }

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

int diffie_hellman_server(int sock) {

    int p = 23, g = 5, b = 15;

    int partial_key_server = mod_exp(g, b, p);
     int partial_key_client;

    recv(sock, &partial_key_client, sizeof(partial_key_client), 0);

    send(sock, &partial_key_server, sizeof(partial_key_server), 0);
     return mod_exp(partial_key_client, b, p);

}

int main() {
    cout <<"server is listeniing...."<<endl;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server_address;

    server_address.sin_family = AF_INET;

    server_address.sin_addr.s_addr = INADDR_ANY;

    server_address.sin_port = htons(8080);
    bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address));

    listen(server_socket, 5);
    client_socket = accept(server_socket, nullptr, nullptr);
    int mutual_key = diffie_hellman_server(client_socket);
     handle_client_requests(mutual_key);
     close(client_socket);

    close(server_socket);

    return 0;

}

