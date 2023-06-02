#include <iostream>
#include <vector>
#include <map>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "../lib/hash.cpp" //Code for processing hashing
#include "../lib/AES.cpp"
#include "../lib/RSA.cpp"
#include "../lib/const.h"

using namespace std;

class Client
{
    int sock = 0;
    struct sockaddr_in serv_addr;
    unsigned char *session_key;

    // Client variables
    unsigned char *client_nonce;
    unsigned char *server_nonce;
    string username; //, user_pub_key_path, user_prv_key_path;

    EVP_PKEY *client_private_key;
    RSA *server_public_key;

    // Available commands
    vector<string> commands = {"login", "balance", "transfer", "transactions"};
    map<string, int> commands_map;
    string current_command;

public:
    Client()
    {
        // cout << "Enter Username:>> ";
        // getline(cin, username);

        cout << "Enter your private Key path:>> ";
        string path = "../keys/sc102.pem";
        // getline(cin, path);
        client_private_key = load_private_key(path.c_str());
        if (!client_private_key)
        {
            cerr << "Error could not load user's private key\n";
            close(sock);
            exit(1);
        }

        // cout << "Enter your public Key path:>> ";
        // path = "../keys/pc102.pem";
        // // getline(cin, path);
        // RSA *client_public_key = load_public_key(path.c_str());
        // if (!client_public_key)
        // {
        //     cerr << "Error could not load user's private key\n";
        //     close(sock);
        //     exit(1);
        // }

        cout << "Enter server public Key path:>> ";
        path = "../pub.pem";
        // getline(cin, path);
        server_public_key = load_public_key(path.c_str());
        if (!server_public_key)
        {
            cerr << "\nError could not load server's public key\n";
            close(sock);
            exit(1);
        }
    }
    // establish connection with server
    void establish_connection()
    {
        // Create socket
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            cout << "\n Socket creation error \n";
            exit(1);
        }

        // Set server address and port
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(SERVER_PORT);

        // Convert IP address from string to binary form
        if (inet_pton(AF_INET, SERVER_ADDR, &serv_addr.sin_addr) <= 0)
        {
            cout << "\nInvalid address/ Address not supported \n";
            exit(1);
        }

        // Connect to server
        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            cout << "\nConnection Failed \n";
            exit(1);
        }

        char buffer[MAX_MSG_LENGTH] = {0};
        read(sock, buffer, MAX_MSG_LENGTH);
        printf("%s\n", buffer);
    }

    // Create and send challenge to the server M1
    void createAndSendEncryptedChallenge()
    {

        int ret;
        // Create client nonce
        client_nonce = (unsigned char *)malloc(NONCE_SIZE);
        if (!client_nonce)
        {
            cerr << "Error allocating buffer for server client nonce\n";
            close(sock);
            exit(1);
        }
        ret = createNonce(client_nonce);
        if (!ret)
        {
            cerr << "Error creating client nonce for server\n";
            close(sock);
            exit(1);
        }

        // read public key for user and concatnate with nonce
        // Allocate buffer for publickey
        size_t pub_len = 0;
        unsigned char *client_public_key = extractPublicKey(client_private_key, pub_len);

        // Concatenate nonce and client's public key
        unsigned char *payload = (unsigned char *)malloc(NONCE_SIZE + pub_len);
        memcpy(payload, client_nonce, NONCE_SIZE);
        memcpy(payload + NONCE_SIZE, client_public_key, pub_len);

        size_t cipher_len = 0;
        unsigned char *encrypted_payload = encryptPubRSA(payload, pub_len + NONCE_SIZE, client_public_key, pub_len, cipher_len);

        sendMessageWithSize(sock, encrypted_payload, cipher_len);

        cout << cipher_len << " Sent: " << bin_to_hex(encrypted_payload, cipher_len).data() << endl;

        // Free
        free(client_nonce);
        free(client_public_key);
        free(payload);
    }

    void exchange_keys()
    {
        // Generate client's DH parameters
        DH *dhParams = DH_new();
        if (!dhParams)
        {
            fprintf(stderr, "Error generating DH parameters\n");
            return;
        }
        if (!DH_generate_parameters_ex(dhParams, 256, DH_GENERATOR_2, nullptr))
        {
            fprintf(stderr, "Error generating DH parameters\n");
            DH_free(dhParams);
            return;
        }

        // Generate client's public-private key pair
        if (!DH_generate_key(dhParams))
        {
            fprintf(stderr, "Error generating client's DH key pair\n");
            DH_free(dhParams);
            return;
        }

        // Encode client's public key to PEM format
        BIO *clientPublicKeyBio = BIO_new(BIO_s_mem());
        if (!clientPublicKeyBio)
        {
            fprintf(stderr, "Error creating BIO for client's public key\n");
            DH_free(dhParams);
            return;
        }
        if (!PEM_write_bio_DHparams(clientPublicKeyBio, dhParams))
        {
            fprintf(stderr, "Error encoding client's public key\n");
            BIO_free(clientPublicKeyBio);
            DH_free(dhParams);
            return;
        }

        char *clientPublicKeyPEM;
        size_t clientPublicKeyPEMLen = BIO_get_mem_data(clientPublicKeyBio, &clientPublicKeyPEM);

        cout << clientPublicKeyPEMLen << "plain text payload: \n"
             << clientPublicKeyPEM << endl;

        // Encrypt client's public key with server's RSA public key
        unsigned char encryptedKey[RSA_size(server_public_key)];
        int encryptedKeyLen = RSA_public_encrypt(static_cast<int>(clientPublicKeyPEMLen),
                                                 reinterpret_cast<const unsigned char *>(clientPublicKeyPEM),
                                                 encryptedKey, server_public_key, RSA_PKCS1_PADDING);
        if (encryptedKeyLen == -1)
        {
            fprintf(stderr, "Error encrypting client's public key\n");
            BIO_free(clientPublicKeyBio);
            DH_free(dhParams);
            return;
        }

        // Send encryptedKey to the server (e.g., over network)
        sendMessageWithSize(sock, encryptedKey, encryptedKeyLen);

        // Cleanup
        BIO_free(clientPublicKeyBio);
        DH_free(dhParams);
    }
};

int main()
{
    // int ret;
    Client user1;

    cout << "Starting client, waiting for server to be available...\n";
    user1.establish_connection();
    cout << "Client successfuly connected to the server\n";

    // user1.createAndSendEncryptedChallenge();
    // cout << "Challenge sent to the server\n";

    user1.exchange_keys();
    cout << "Exchanged keys Succesfully.\n";
}
/*
int main(int argc, char *argv[])
{
    try
    {
        int sock = 0;
        struct sockaddr_in serv_addr;
        unsigned char *session_key;

        // Create socket
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            printf("\n Socket creation error \n");
            return -1;
        }

        // Set server address and port
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(SERVER_PORT);

        // Convert IP address from string to binary form
        if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0)
        {
            printf("\nInvalid address/ Address not supported \n");
            return -1;
        }

        // Connect to server
        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            printf("\nConnection Failed \n");
            return -1;
        }
        char buffer[MAX_MSG_LENGTH] = {0};
        read(sock, buffer, MAX_MSG_LENGTH);
        printf("%s\n", buffer);

        // exchange session key

        // // login
        // char command[MAX_COMMAND_LENGTH];
        // char username[MAX_FIELD_LENGTH], password[MAX_FIELD_LENGTH];
        // printf("Enter username: ");
        // fgets(username, MAX_FIELD_LENGTH, stdin);
        // strtok(username, "\n");
        // printf("Enter password: ");
        // fgets(password, MAX_FIELD_LENGTH, stdin);
        // strtok(password, "\n");

        // // Construct login message
        // char message[MAX_COMMAND_LENGTH + (2 * MAX_FIELD_LENGTH)];
        // sprintf(message, "%s:%s:%s", "login", username, password);
        // // encrypt with servers public key
        // string payload = encryptPubRSAFile(message, "../pub.pem");
        // // string payload = encryptPubRSA(message, pubkey_tostring(load_public_key("../pub.pem")));
        // send(sock, payload.data(), payload.size(), 0);
        // // send(sock, message, strlen(message), 0);

        // buffer[MAX_MSG_LENGTH] = {0};
        // int len = read(sock, buffer, MAX_MSG_LENGTH);
        // string bufferStr(buffer, len);
        // if (bufferStr.substr(0, 5) == "ERROR")
        // {
        //     printf("Error Happend(try again)%d: \n%s\n", len, bufferStr.data());
        //     exit(1);
        // }

        // printf("encrypted%d: %s\n", len, bin_to_hex((unsigned char *)buffer, len).data());
        // string decrypted = decryptPrvRSA(bufferStr, "../keys/sc102.pem");
        // printf("decrypted: %s\n", decrypted.data());
        // vector<string> parts = split(decrypted, ':');
        // session_key = (unsigned char *)(from_hex_string(parts[1]).data());
        // // printf("decrypted session key: %s\n", bin_to_hex((unsigned char *)session_key, parts[1].size() / 2).data());
        // // printf("decrypted session key: %s", bin_to_hex((unsigned char *)from_hex_string(parts[1]).data(), from_hex_string(parts[1]).size()).data());

        // // Loop for sending commands to server
        // while (1)
        // {
        //     printf("Enter command (balance, or transfer): ");
        //     fgets(command, MAX_COMMAND_LENGTH, stdin);
        //     strtok(command, "\n"); // Remove newline character from input

        //     // Send balance command with username
        //     if (strcmp(command, "balance") == 0)
        //     {
        //         // char username[MAX_FIELD_LENGTH];
        //         // printf("Enter username: ");
        //         // fgets(username, MAX_FIELD_LENGTH, stdin);
        //         // strtok(username, "\n");

        //         // Construct balance message
        //         char message[MAX_COMMAND_LENGTH + MAX_FIELD_LENGTH] = {0};
        //         sprintf(message, "%s:%s", command, username);

        //         // encrypt command
        //         size_t ciphertextLength, dectextlength;
        //         unsigned char *ciphertext = (unsigned char *)malloc(BUFFER_SIZE);
        //         ciphertextLength = encryptSym((unsigned char *)message, strlen(message), ciphertext, session_key);
        //         printf("sending payload aes %d Encrypted: %s :=> %s \n", ciphertextLength, message, bin_to_hex(ciphertext, ciphertextLength + ivSize).data());
        //         unsigned char *decodeText = (unsigned char *)malloc(BUFFER_SIZE);
        //         dectextlength = decryptSym(ciphertext, ciphertextLength, decodeText, session_key);
        //         printf("Decrypted Text: %.*s\n", static_cast<int>(dectextlength), decodeText);

        //         // Send message to server
        //         send(sock, ciphertext, ciphertextLength + ivSize, 0);

        //         // Receive response from server
        //         char buffer[MAX_COMMAND_LENGTH] = {0};
        //         len = read(sock, buffer, MAX_COMMAND_LENGTH);
        //         dectextlength = decryptSym((unsigned char *)(payload.data()), ciphertextLength, decodeText, session_key);

        //         printf("recived balance: %s\n", payload);
        //     }

        //     // Send transfer command with username and amount
        //     else if (strcmp(command, "transfer") == 0)
        //     {
        //         char username[MAX_FIELD_LENGTH];
        //         double amount;
        //         printf("Enter username: ");
        //         fgets(username, MAX_FIELD_LENGTH, stdin);
        //         strtok(username, "\n");
        //         printf("Enter amount: ");
        //         scanf("%lf", &amount);
        //         getchar(); // Remove newline character from input

        //         // Construct transfer message
        //         char message[MAX_COMMAND_LENGTH + MAX_FIELD_LENGTH];
        //         sprintf(message, "%s:%s:%s", command, username, amount);

        //         // Send message to server
        //         send(sock, message, strlen(message), 0);

        //         // Receive response from server
        //         char buffer[MAX_COMMAND_LENGTH] = {0};
        //         read(sock, buffer, MAX_COMMAND_LENGTH);
        //         printf("%s\n", buffer);
        //     }
        // }
    }
    catch (const std::exception &e)
    {
        cerr << e.what() << '\n';
    }
}
*/