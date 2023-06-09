#include <iostream>
#include <vector>
#include <map>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <termios.h>
#include "../lib/hash.cpp" //Code for processing hashing
#include "../lib/RSA.cpp"
#include "../lib/db.cpp" //Code for processing db
#include "../lib/EC.cpp"
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
    string username;
    EVP_PKEY *client_private_key;
    EVP_PKEY *server_public_key;

    // Available commands
    vector<string> commands = {"login", "balance", "transfer", "transactions"};
    map<string, int> commands_map;
    string current_command;

    string getPassword()
    {
        string password;
        termios oldSettings, newSettings;

        // Disable terminal echoing
        tcgetattr(STDIN_FILENO, &oldSettings);
        newSettings = oldSettings;
        newSettings.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newSettings);

        // Read the password
        getline(cin, password);

        // Enable terminal echoing
        tcsetattr(STDIN_FILENO, TCSANOW, &oldSettings);

        return password;
    }

public:
    Client()
    {
        cout << "Enter Username:>> ";
        username = "a";
        // getline(cin, username);

        cout << "\nEnter your private Key path:>> ";
        string path = "../keys/sc149.pem";
        // getline(cin, path);
        client_private_key = rsa::load_private_key(path.c_str());
        if (!client_private_key)
        {
            cerr << "\n!Error could not load user's private key\n";
            close(sock);
            exit(1);
        }

        // cout << "Enter your public Key path:>> ";
        // path = "../keys/pc139.pem";
        // // getline(cin, path);
        // RSA *client_public_key = load_public_key(path.c_str());
        // if (!client_public_key)
        // {
        //     cerr << "Error could not load user's private key\n";
        //     close(sock);
        //     exit(1);
        // }

        cout << "Enter server public Key path:>> ";
        path = "../keys/server_pub.pem";
        // getline(cin, path);
        server_public_key = convertToEVP(load_public_key(path.c_str()));
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

    // // Create and send challenge to the server M1
    // void createAndSendEncryptedChallenge()
    // {

    //     int ret;
    //     // Create client nonce
    //     client_nonce = (unsigned char *)malloc(NONCE_SIZE);
    //     if (!client_nonce)
    //     {
    //         cerr << "Error allocating buffer for server client nonce\n";
    //         close(sock);
    //         exit(1);
    //     }
    //     ret = createNonce(client_nonce);
    //     if (!ret)
    //     {
    //         cerr << "Error creating client nonce for server\n";
    //         close(sock);
    //         exit(1);
    //     }

    //     // read public key for user and concatnate with nonce
    //     // Allocate buffer for publickey
    //     size_t pub_len = 0;
    //     unsigned char *client_public_key = extractPublicKey(client_private_key, pub_len);

    //     // Concatenate nonce and client's public key
    //     unsigned char *payload = (unsigned char *)malloc(NONCE_SIZE + pub_len);
    //     memcpy(payload, client_nonce, NONCE_SIZE);
    //     memcpy(payload + NONCE_SIZE, client_public_key, pub_len);

    //     size_t cipher_len = 0;
    //     unsigned char *encrypted_payload = encryptPubRSA(payload, pub_len + NONCE_SIZE, client_public_key, pub_len, cipher_len);

    //     sendMessageWithSize(sock, encrypted_payload, cipher_len);

    //     cout << cipher_len << " Sent: " << bin_to_hex(encrypted_payload, cipher_len).data() << endl;

    //     // Free
    //     free(client_nonce);
    //     free(client_public_key);
    //     free(payload);
    // }

    void exchange_keys()
    {
        // Generate client's ephemeral ECDH private key
        EC_KEY *client_key = generateECDHEC_KEY();

        size_t pub_len = 0;
        unsigned char *client_public_key = extractPublicKey(client_key, pub_len);
        unsigned char *cpk = extractPrivateKey(client_key, pub_len);

        // Send temprory public key to the server (e.g., over network) M1
        sendMessageWithSize(sock, client_public_key, pub_len);
        cout << "PEM: \n"
             << client_public_key << endl
             << cpk;

        printECDH("Client pub_key: ", convertToEVP(client_key));
        printECDH("Server pub_key: ", server_public_key);

        // Generate shared secret
        size_t secret_length = 0;
        session_key = deriveSharedKey(convertToEVP(client_key), server_public_key, &secret_length);
        cout << "Client shared Secret: ";
        for (int i = 0; i < secret_length; i++)
        {
            printf("%02x", session_key[i]);
        }
        cout << endl;

        // Cleanup
        EC_KEY_free(client_key);
        free(client_public_key);
    }

    void authenticateWithServer()
    {
        unsigned int message_len = 0;
        unsigned char *message = recieveAndDecryptMsg(sock, &message_len, session_key);
        cout << "Authenticated with server: " << message << endl;
    }
    void login()
    {
        cout << ">> Enter password: ";
        string password = getPassword();
        cout << endl;
        string command = ToString(Commands::Login) + ":" + username + ":" + password;
        encryptAndSendmsg(sock, (unsigned char *)command.c_str(), command.size(), session_key);

        unsigned int result_len = 0;
        unsigned char *result = recieveAndDecryptMsg(sock, &result_len, session_key);
        string result_str((char *)result, result_len);
        switch (resolveResponse(result_str))
        {
        case Response::ERROR:
            /* code */
            cout << "Try again Error Happend: " << result_str << endl;
            login();
            break;
        default:
            cout << "loggedin Seccuessfully: " << result_str << endl;
            break;
        }
    }
    void handleCommands()
    {
        unsigned int result_len = 0;
        unsigned char *result;
        string command;
        // Loop for sending commands to server
        while (1)
        {
            cout << "Enter command (balance, transfer, list, exit): ";
            getline(cin, current_command);

            // Send balance command with username
            if (current_command == "balance" || current_command == "0")
            {
                // Construct balance message
                command = to_string(Commands::Balance);

                // encrypt command
                encryptAndSendmsg(sock, (unsigned char *)command.c_str(), command.size(), session_key);

                // Receive response from server

                result = recieveAndDecryptMsg(sock, &result_len, session_key);
                cout << "balance is: " << split(string((char *)result, result_len), ':')[1] << endl;
            }
            // Send transfer command with username and amount
            else if (current_command == "transfer" || current_command == "1")
            {
                string reciever, amount;
                cout << "Enter reciever's username: ";
                getline(cin, reciever);
                cout << "Enter amount to transfer: ";
                getline(cin, amount);
                while (stod(amount) < 0)
                {
                    cout << "Wrong amount it should be number, Enter amount: ";
                    getline(cin, amount);
                }

                // encrypt command
                command = to_string(Commands::Transfer) + ":" + reciever + ":" + amount;
                encryptAndSendmsg(sock, (unsigned char *)command.c_str(), command.size(), session_key);

                // Receive response from server
                result_len = 0;
                result = recieveAndDecryptMsg(sock, &result_len, session_key);
                string result_str((char *)result, result_len);
                switch (resolveResponse(result_str))
                {
                case Response::ERROR:
                    cout << "Couldn't Transfer: " << result_str << endl;
                    break;
                default:
                    cout << "Transferred Seccuessfully: " << result_str << endl;
                    break;
                }
            }
            // Send transfer command with username and amount
            else if (current_command == "list" || current_command == "2")
            {
                command = to_string(Commands::List);

                // encrypt command
                encryptAndSendmsg(sock, (unsigned char *)command.c_str(), command.size(), session_key);

                // Receive response from server
                result = recieveAndDecryptMsg(sock, &result_len, session_key);
                std::vector<sba_transaction_t> trxs = deserializeTransactionsFromString(split(string((char *)result, result_len), ':')[1]);
                for (const auto &transaction : trxs)
                {
                    string cipher = base64_decode(transaction.encTransaction);
                    size_t plaintext_len = 0;
                    unsigned char *plaintext = rsa::decryptPrvRSA((unsigned char *)cipher.c_str(), size_t(cipher.size()), client_private_key, plaintext_len);
                    string trx = string((char *)plaintext, plaintext_len);
                    std::cout
                        << "ID: " << transaction.id << ", UserID: " << transaction.userId << ", Transaction: " << trx << std::endl;
                }
            }
            // Send transfer command with username and amount
            else if (current_command == "exit" || current_command == "3")
            {
                exit(0);
            }
            else
            {
                cout << "Not a valid command try agian." << endl;
                continue;
            }

            free(result);
        }
    }
};

int main()
{
    // int ret;
    Client user1;
    string command;

    cout << "Starting client, waiting for server to be available...\n";
    user1.establish_connection();
    cout << "Client successfuly connected to the server\n";

    // user1.createAndSendEncryptedChallenge();
    // cout << "Challenge sent to the server\n";

    user1.exchange_keys();
    cout << "Exchanged keys Succesfully.\n";

    user1.authenticateWithServer();
    cout << "Authenticated Session Key.\n";

    user1.login();
    cout << "loggedin with username password.\n";

    user1.handleCommands();
    cout << "exiting.\n";
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
        //         ciphertextLength = encryptAES((unsigned char *)message, strlen(message), ciphertext, session_key);
        //         printf("sending payload aes %d Encrypted: %s :=> %s \n", ciphertextLength, message, bin_to_hex(ciphertext, ciphertextLength + ivSize).data());
        //         unsigned char *decodeText = (unsigned char *)malloc(BUFFER_SIZE);
        //         dectextlength = decryptAES(ciphertext, ciphertextLength, decodeText, session_key);
        //         printf("Decrypted Text: %.*s\n", static_cast<int>(dectextlength), decodeText);

        //         // Send message to server
        //         send(sock, ciphertext, ciphertextLength + ivSize, 0);

        //         // Receive response from server
        //         char buffer[MAX_COMMAND_LENGTH] = {0};
        //         len = read(sock, buffer, MAX_COMMAND_LENGTH);
        //         dectextlength = decryptAES((unsigned char *)(payload.data()), ciphertextLength, decodeText, session_key);

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
    catch (const exception &e)
    {
        cerr << e.what() << '\n';
    }
}
*/