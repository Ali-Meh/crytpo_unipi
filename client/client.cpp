#include <iostream>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "../lib/hash.cpp" //Code for processing hashing
#include "../lib/AES.cpp"
#include "../lib/RSA.cpp"

using namespace std;

#define PORT 8080
#define MAX_COMMAND_LENGTH 128
#define MAX_FIELD_LENGTH 255
#define MAX_MSG_LENGTH 1024

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
        serv_addr.sin_port = htons(PORT);

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

        // login
        char command[MAX_COMMAND_LENGTH];
        char username[MAX_FIELD_LENGTH], password[MAX_FIELD_LENGTH];
        printf("Enter username: ");
        fgets(username, MAX_FIELD_LENGTH, stdin);
        strtok(username, "\n");
        printf("Enter password: ");
        fgets(password, MAX_FIELD_LENGTH, stdin);
        strtok(password, "\n");

        // Construct login message
        char message[MAX_COMMAND_LENGTH + (2 * MAX_FIELD_LENGTH)];
        sprintf(message, "%s:%s:%s", "login", username, password);
        // encrypt with servers public key
        string payload = encryptPubRSAFile(message, "../pub.pem");
        // string payload = encryptPubRSA(message, pubkey_tostring(load_public_key("../pub.pem")));
        send(sock, payload.data(), payload.size(), 0);
        // send(sock, message, strlen(message), 0);

        buffer[MAX_MSG_LENGTH] = {0};
        int len = read(sock, buffer, MAX_MSG_LENGTH);
        string bufferStr(buffer, len);
        if (bufferStr.substr(0, 5) == "ERROR")
        {
            printf("Error Happend(try again)%d: \n%s\n", len, bufferStr.data());
            exit(1);
        }

        printf("encrypted%d: %s\n", len, bin_to_hex((unsigned char *)buffer, len).data());
        string decrypted = decryptPrvRSA(bufferStr, "../keys/sc102.pem");
        printf("decrypted: %s\n", decrypted.data());
        vector<string> parts = split(decrypted, ':');
        session_key = (unsigned char *)(from_hex_string(parts[1]).data());
        // printf("decrypted session key: %s\n", bin_to_hex((unsigned char *)session_key, parts[1].size() / 2).data());
        // printf("decrypted session key: %s", bin_to_hex((unsigned char *)from_hex_string(parts[1]).data(), from_hex_string(parts[1]).size()).data());

        // Loop for sending commands to server
        while (1)
        {
            printf("Enter command (balance, or transfer): ");
            fgets(command, MAX_COMMAND_LENGTH, stdin);
            strtok(command, "\n"); // Remove newline character from input

            // // Send login command with username and password
            // if (strcmp(command, "login") == 0)
            // {
            //     char username[MAX_FIELD_LENGTH], password[MAX_FIELD_LENGTH];
            //     printf("Enter username: ");
            //     fgets(username, MAX_FIELD_LENGTH, stdin);
            //     strtok(username, "\n");
            //     printf("Enter password: ");
            //     fgets(password, MAX_FIELD_LENGTH, stdin);
            //     strtok(password, "\n");

            //     // Construct login message
            //     char message[MAX_COMMAND_LENGTH + (2 * MAX_FIELD_LENGTH)];
            //     sprintf(message, "%s:%s:%s", command, username, password);

            //     // Send message to server
            //     send(sock, message, strlen(message), 0);

            //     // Receive response from server
            //     char buffer[MAX_COMMAND_LENGTH] = {0};
            //     read(sock, buffer, MAX_COMMAND_LENGTH);
            //     printf("%s\n", buffer);
            // }

            // Send balance command with username
            if (strcmp(command, "balance") == 0)
            {
                // char username[MAX_FIELD_LENGTH];
                // printf("Enter username: ");
                // fgets(username, MAX_FIELD_LENGTH, stdin);
                // strtok(username, "\n");

                // Construct balance message
                char message[MAX_COMMAND_LENGTH + MAX_FIELD_LENGTH] = {0};
                sprintf(message, "%s:%s", command, username);

                // encrypt command
                size_t ciphertextLength, dectextlength;
                unsigned char *ciphertext = (unsigned char *)malloc(BUFFER_SIZE);
                ciphertextLength = encryptSym((unsigned char *)message, strlen(message), ciphertext, session_key);
                printf("sending payload aes %d Encrypted: %s :=> %s \n", ciphertextLength, message, bin_to_hex(ciphertext, ciphertextLength + ivSize).data());
                unsigned char *decodeText = (unsigned char *)malloc(BUFFER_SIZE);
                dectextlength = decryptSym(ciphertext, ciphertextLength, decodeText, session_key);
                printf("Decrypted Text: %.*s\n", static_cast<int>(dectextlength), decodeText);

                // Send message to server
                send(sock, ciphertext, ciphertextLength + ivSize, 0);

                // Receive response from server
                char buffer[MAX_COMMAND_LENGTH] = {0};
                len = read(sock, buffer, MAX_COMMAND_LENGTH);
                dectextlength = decryptSym((unsigned char *)(payload.data()), ciphertextLength, decodeText, session_key);

                printf("recived balance: %s\n", payload);
            }

            // Send transfer command with username and amount
            else if (strcmp(command, "transfer") == 0)
            {
                char username[MAX_FIELD_LENGTH];
                double amount;
                printf("Enter username: ");
                fgets(username, MAX_FIELD_LENGTH, stdin);
                strtok(username, "\n");
                printf("Enter amount: ");
                scanf("%lf", &amount);
                getchar(); // Remove newline character from input

                // Construct transfer message
                char message[MAX_COMMAND_LENGTH + MAX_FIELD_LENGTH];
                sprintf(message, "%s:%s:%s", command, username, amount);

                // Send message to server
                send(sock, message, strlen(message), 0);

                // Receive response from server
                char buffer[MAX_COMMAND_LENGTH] = {0};
                read(sock, buffer, MAX_COMMAND_LENGTH);
                printf("%s\n", buffer);
            }
        }
    }
    catch (const std::exception &e)
    {
        cerr << e.what() << '\n';
    }
}
