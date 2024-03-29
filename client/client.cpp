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
    uint counter = 0;
    string username;
    EVP_PKEY *client_private_key;
    EC_KEY *client_key;

    // Available commands
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
        cout << "Enter Username:>> (a) ";
        getline(cin, username);
        if (username.empty())
            username = "a";

        cout << "\nEnter your private Key path:>> (../keys/sc169.pem)";
        string path;
        getline(cin, path);
        if (path.empty())
            path = "../keys/sc169.pem";
        client_private_key = rsa::load_private_key(path.c_str());
        if (!client_private_key)
        {
            cerr << "\n!Error could not load user's private key\n";
            close(sock);
            exit(1);
        }
    }
    ~Client()
    {
        EC_KEY_free(client_key);
        EVP_PKEY_free(client_private_key);
        free(client_nonce);
        free(session_key);
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
    void createAndSendChallengeWithClientPub()
    {

        // Create client nonce
        client_nonce = createNonce();
        if (!client_nonce)
        {
            cerr << "Error creating client nonce for server\n";
            close(sock);
            exit(1);
        }

        // Generate client's ephemeral ECDH private key
        client_key = generateECDHEC_KEY();

        size_t pub_len = 0;
        // read public key for user and concatnate with nonce
        unsigned char *client_public_key = extractPublicKey(client_key, pub_len);

        // Concatenate nonce and client's public key
        size_t payload_len = NONCE_SIZE + pub_len;
        unsigned char *payload = (unsigned char *)malloc(payload_len);
        memcpy(payload, client_nonce, NONCE_SIZE);
        memcpy(payload + NONCE_SIZE, client_public_key, pub_len);

        sendMessageWithSize(sock, payload, payload_len);

        if (PRINT_MESSAGES)
            cout << "<<M1: \n"
                 << string((char *)payload, payload_len) << endl;

        // Free
        free(client_nonce);
        delete[] client_public_key;
        free(payload);
    }

    // Receive Certificate and derive Shared Key M2
    void exchange_keys()
    {
        unsigned int cert_len = 0;
        unsigned char *cert_str = recieveSizedMessage(sock, &cert_len);
        if (PRINT_MESSAGES)
            cout << ">>M2: \n"
                 << string((char *)cert_str, cert_len) << endl;
        X509 *certificate = pemToX509(string((char *)cert_str, cert_len));
        free(cert_str);
        if (!certificate)
        {
            cerr << "Failed to receive the server's certificate." << endl;
            close(sock);
            exit(EXIT_FAILURE);
        }
        if (!verifyCertificate(certificate))
        {
            cerr << "Failed to verify the server's certificate." << endl;
            X509_free(certificate);
            close(sock);
            exit(EXIT_FAILURE);
        }

        EVP_PKEY *server_public_key = X509_get_pubkey(certificate);
        if (!server_public_key)
        {
            cerr << "Failed to extract server's public key." << endl;
            X509_free(certificate);
            EVP_PKEY_free(server_public_key);
            close(sock);
            exit(EXIT_FAILURE);
        }
        EVP_PKEY *key = convertToEVP(client_key);
        if (PRINT_MESSAGES)
        {
            printECDH("Client pub_key: ", key);
            printECDH("Server pub_key: ", server_public_key);
        }

        // Generate shared secret
        size_t secret_length = 0;
        session_key = deriveSharedKey(key, server_public_key, &secret_length);
        cout << "Client shared Secret: ";
        for (size_t i = 0; i < secret_length; i++)
        {
            printf("%02x", session_key[i]);
        }
        cout << endl;

        // Cleanup
        EC_KEY_free(client_key);
        EVP_PKEY_free(server_public_key);
        EVP_PKEY_free(key);
        X509_free(certificate);
    }
    // receive M3{Ns||Nc||Cs}k and send M4{Ns||Cs+1}k
    void authenticateWithServer()
    {
        unsigned int message_len = 0;
        unsigned char *message = recieveAndDecryptMsg(sock, &message_len, &counter, session_key);
        if (PRINT_MESSAGES)
            cout << ">>M3: \n"
                 << bin_to_hex(message, message_len) << endl;
        // client Nonce doesn't match
        if (!memcmp(message + NONCE_SIZE, client_nonce, NONCE_SIZE))
        {
            cerr << "Failed to authenticate with server (Client Nonce Don't match).\n"
                 << bin_to_hex(message + NONCE_SIZE, NONCE_SIZE) << "!=\n"
                 << bin_to_hex(client_nonce, NONCE_SIZE) << endl;
            close(sock);
            exit(EXIT_FAILURE);
        }
        cout << "Authenticated with server counter: " << counter << endl;
        if (PRINT_MESSAGES)
            cout << "<< M4: \n"
                 << string((char *)message, NONCE_SIZE) << " " << counter << endl;
        encryptAndSendmsg(sock, message, NONCE_SIZE, &counter, session_key);
        free(message);
    }
    void login()
    {
        cout << ">> Enter password: ";
        string password = getPassword();
        cout << endl;
        string command = ToString(Commands::Login) + ":" + username + ":" + password;
        encryptAndSendmsg(sock, (unsigned char *)command.c_str(), command.size(), &counter, session_key);

        unsigned int result_len = 0;
        unsigned char *result = recieveAndDecryptMsg(sock, &result_len, &counter, session_key);
        if (result == nullptr)
        {
            cout << "Couldn't decrypt the message: " << endl;
            return;
        }
        string result_str((char *)result, result_len);
        free(result);
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
                encryptAndSendmsg(sock, (unsigned char *)command.c_str(), command.size(), &counter, session_key);

                // Receive response from server

                result = recieveAndDecryptMsg(sock, &result_len, &counter, session_key);
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
                encryptAndSendmsg(sock, (unsigned char *)command.c_str(), command.size(), &counter, session_key);

                // Receive response from server
                result_len = 0;
                result = recieveAndDecryptMsg(sock, &result_len, &counter, session_key);
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
                encryptAndSendmsg(sock, (unsigned char *)command.c_str(), command.size(), &counter, session_key);

                // Receive response from server
                result = recieveAndDecryptMsg(sock, &result_len, &counter, session_key);
                size_t plaintext_len = 0;
                unsigned char *plaintext;
                vector<sba_transaction_t> trxs = deserializeTransactionsFromString(split(string((char *)result, result_len), ':')[1]);
                for (const auto &transaction : trxs)
                {
                    string cipher = base64_decode(transaction.encTransaction);
                    plaintext = rsa::decryptPrvRSA((unsigned char *)cipher.c_str(), size_t(cipher.size()), client_private_key, plaintext_len);
                    string trx = string((char *)plaintext, plaintext_len);
                    cout
                        << "ID: " << transaction.id << ", UserID: " << transaction.userId << ", Transaction: " << trx << endl;
                    delete[] plaintext;
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

    user1.createAndSendChallengeWithClientPub();
    cout << "Challenge With client public Key sent to the server\n";

    user1.exchange_keys();
    cout << "Exchanged keys Succesfully.\n";

    user1.authenticateWithServer();
    cout << "Authenticated Session Key.\n";

    user1.login();
    cout << "loggedin with username password.\n";

    user1.handleCommands();
    cout << "exiting.\n";
}
