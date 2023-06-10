// Example code: A simple server side code, which echos back the received message.
// Handle multiple socket connections with select and fd_set on Linux
#include <stdio.h>
#include <string.h> //strlen
#include <cstring>
#include "vector"
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>    //close
#include <arpa/inet.h> //close
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>      //FD_SET, FD_ISSET, FD_ZERO macros
#include "../lib/EC.cpp"   //Code for processing [a]symectric encryptions
#include "../lib/RSA.cpp"  //Code for processing [a]symectric encryptions
#include "../lib/db.cpp"   //Code for processing db
#include "../lib/hash.cpp" //Code for processing hashing
#include "../lib/const.h"  //Code for processing symectric encryptions

using namespace std;

/* Structure describing an Internet socket address.  */
class sba_client_conn
{
public:
    bool in_use;
    int sd;                    /*Socket Descriptor*/
    string session_key;        /*Session key for secure connection*/
    sba_client_t user_session; /*username session belongs to*/
    int valid_until;           /*Session key validity period*/

    bool isLoggedIn()
    {
        return sizeof(user_session) > 0 && !std::is_empty<sba_client_t>::value;
    }

    int exchange_keys(EVP_PKEY *ec_key)
    {
        // Recieve temprory public key from client M1
        unsigned int pub_len = 0;
        unsigned char *peer_pubkey = recieveSizedMessage(sd, &pub_len);
        cout << "PEM: \n"
             << peer_pubkey;
        // Print the public key in hexadecimal format
        EVP_PKEY *peer_pub_key = convertToEVP(peer_pubkey, pub_len);

        printECDH("Recived Client pub_key: ", peer_pub_key);
        printECDH("Server pub_key: ", ec_key);

        // Generate shared secret
        size_t secret_length = 0;
        unsigned char *sk = deriveSharedKey(ec_key, peer_pub_key, &secret_length);

        session_key = string((char *)sk, secret_length);

        std::cout << "Server shared Secret: ";
        for (size_t i = 0; i < session_key.size(); ++i)
        {
            unsigned char byte = static_cast<unsigned char>(session_key[i]);
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::cout << std::dec << std::endl;

        // send NonceFor Authentication
        unsigned char *nonce = (unsigned char *)malloc(NONCE_SIZE);
        int ret = createNonce(nonce);
        if (ret < 0)
            cerr << "couln't create Nonce\n";

        // int cipher_len = 0;
        // unsigned char *cipher = crypter::encryptAES(nonce, NONCE_SIZE, &cipher_len, (unsigned char *)session_key.c_str());

        // cout << "<< Sending M2 Encrypted Nonce with sessionKey: " << bin_to_hex(nonce, NONCE_SIZE) << endl;
        // sendMessageWithSize(sd, cipher, cipher_len);

        encryptAndSendmsg(sd, nonce, NONCE_SIZE, (unsigned char *)session_key.c_str());

        // Cleanup
        EVP_PKEY_free(peer_pub_key);
        free(peer_pubkey);
        free(sk);
        return 1;
    }
};

class Server
{
    int opt = TRUE;
    const static int max_clients = 30;
    int master_socket, addrlen, new_socket, activity, i, valread, sd, max_sd;
    sba_client_conn client_sockets[max_clients];
    EC_KEY *private_key;

    // set of socket descriptors
    fd_set readfds;
    sqlite3 *db;
    struct sockaddr_in address;
    char buffer[BUFFER_SIZE]; // data buffer of 1K

    // welcome message
    char *message = (char *)"Welcome to SBA server v1.0 \r\n";
    void close_and_free_socket(sba_client_conn *client_socket)
    {
        // Close the socket and mark as 0 in list for reuse
        close(client_socket->sd);
        client_socket->in_use = false;
        client_socket->sd = 0;
        client_socket->session_key = "";
    }
    void onClientDisconnect(sba_client_conn *client_socket)
    {
        // Somebody disconnected , get his details and print
        getpeername(client_socket->sd, (struct sockaddr *)&address,
                    (socklen_t *)&addrlen);
        printf("Host disconnected , ip %s , port %d, sock %d\n",
               inet_ntoa(address.sin_addr), ntohs(address.sin_port), client_socket->sd);

        // Close the socket and mark as 0 in list for reuse
        close_and_free_socket(client_socket);
    }
    // checks whether user is loggedin or not if not will send unauthorized Message to user
    int checkUserIsAuthenticated(sba_client_conn *client_socket)
    {
        int ret = 1;
        if (!(*client_socket).isLoggedIn())
        {
            // send unAuthorized to the client
            string result = Errors::NotAuthorized + ":";
            ret = encryptAndSendmsg((*client_socket).sd, (unsigned char *)result.c_str(), result.size(), (unsigned char *)(*client_socket).session_key.c_str());
            if (ret < 0)
            {
                cerr << "Error:checkUserIsAuthenticated: Not able to send Error message" << endl;
            }
        }
        return ret;
    }

public:
    Server(string db_path = "../SBA.db")
    {
        db = connect(db_path);
        // initialise all client_socket[] to 0 so not checked
        for (i = 0; i < max_clients; i++)
        {
            client_sockets[i].in_use = false;
            client_sockets[i].sd = 0;
        }

        string path = "../keys/server_sec.pem";
        // getline(cin, path);
        private_key = load_private_key(path.c_str());
        if (!private_key)
        {
            cerr << "Error could not load servers's private key\n";
            exit(1);
        }
    }
    int onLogin(vector<string> args, sba_client_conn *conn)
    {
        cout << "onLogin..." << endl;
        vector<sba_client_t> db_users = getClientByUsername(db, args[1]);
        if (db_users.empty() || !verify_password(args[2], db_users[0].password))
        {
            string result = generateResult(Errors::WrongCredentials, "you might retry");
            encryptAndSendmsg((*conn).sd, (unsigned char *)result.c_str(), result.size(), (unsigned char *)(*conn).session_key.c_str());
            return 0;
        }
        printf("found user id %d\n", db_users[0].id);
        (*conn).user_session = db_users[0];
        cout << "user logged in as: " << (*conn).user_session.username << endl;
        string result = generateResult(Errors::Null, "Loggedin Successfully as " + (*conn).user_session.username);
        encryptAndSendmsg((*conn).sd, (unsigned char *)result.c_str(), result.size(), (unsigned char *)(*conn).session_key.c_str());
        return 1;
    }
    int onBalance(vector<string> args, sba_client_conn conn)
    {
        cout << "onBalance..." << endl;
        vector<sba_client_t> db_users = getClientByUsername(db, conn.user_session.username);
        if (db_users.empty())
        {
            string result = generateResult(Errors::NotFound);
            encryptAndSendmsg(conn.sd, (unsigned char *)result.c_str(), result.size(), (unsigned char *)conn.session_key.c_str());
            return 0;
        }
        printf("balance found user id %d\n", db_users[0].id);
        conn.user_session = db_users[0];
        string result = generateResult(Errors::Null, to_string(conn.user_session.balance));
        encryptAndSendmsg(conn.sd, (unsigned char *)result.c_str(), result.size(), (unsigned char *)conn.session_key.c_str());
        return 1;
    }
    int onTransfer(vector<string> args, sba_client_conn conn)
    {
        double amount = stod(args[2]);
        sba_client_t sender, receiver;
        cout << "onTransfer... from " << conn.user_session.username
             << " to " << args[1]
             << " $" << amount << endl;
        vector<sba_client_t> db_users = getClientByUsername(db, conn.user_session.username);
        // get sender user
        if (db_users.empty())
        {
            string result = generateResult(Errors::NotFound);
            encryptAndSendmsg(conn.sd, (unsigned char *)result.c_str(), result.size(), (unsigned char *)conn.session_key.c_str());
            return 0;
        }
        else if (db_users[0].balance < amount)
        {
            string result = generateResult(Errors::NotEnoughFunds, "Not Enough Funds...");
            encryptAndSendmsg(conn.sd, (unsigned char *)result.c_str(), result.size(), (unsigned char *)conn.session_key.c_str());
            return 0;
        }
        sender = db_users[0];

        // get sender user
        db_users = getClientByUsername(db, args[1]);
        if (db_users.empty())
        {
            string result = generateResult(Errors::NotFound, "reciever doesn't exist");
            encryptAndSendmsg(conn.sd, (unsigned char *)result.c_str(), result.size(), (unsigned char *)conn.session_key.c_str());
            return 0;
        }
        receiver = db_users[0];

        // transfer funds
        // save encrypted version on server db
        time_t stamp;
        time(&stamp);
        string trx_msg(receiver.username + ":" + to_string(amount) + ":" + to_string(stamp));
        string enc_trx = rsa::encryptPubRSA(trx_msg, sender.pubkey);

        sba_transaction_t transaction = {0, sender.id, base64_encode(enc_trx)};
        if (transferToReceiver(db, transaction, receiver.id, amount) != 0)
        {
            string result = generateResult(Errors::Todo);
            encryptAndSendmsg(conn.sd, (unsigned char *)result.c_str(), result.size(), (unsigned char *)conn.session_key.c_str());
            return 0;
        }

        string result = generateResult(Errors::Null, to_string(amount) + "$ to " + receiver.username);
        encryptAndSendmsg(conn.sd, (unsigned char *)result.c_str(), result.size(), (unsigned char *)conn.session_key.c_str());
        return 1;
    }
    int onList(vector<string> args, sba_client_conn conn)
    {
        cout << "onList... " << endl;
        vector<sba_transaction_t> db_transactions = getTransactionsById(db, conn.user_session.id);
        if (db_transactions.empty())
        {
            string result = generateResult(Errors::NotFound);
            encryptAndSendmsg(conn.sd, (unsigned char *)result.c_str(), result.size(), (unsigned char *)conn.session_key.c_str());
            return 0;
        }
        if (PRINT_MESSAGES)
        {
            for (const auto &transaction : db_transactions)
            {
                std::cout
                    << "ID: " << transaction.id << ", UserID: " << transaction.userId << ", encTransaction: " << transaction.encTransaction << std::endl;
            }
        }

        string result = generateResult(Errors::Null, serializeTransactionsToString(db_transactions));
        encryptAndSendmsg(conn.sd, (unsigned char *)result.c_str(), result.size(), (unsigned char *)conn.session_key.c_str());
        return 1;
    }

    void start_server(int port = SERVER_PORT)
    {
        // create a master socket
        if ((master_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
        {
            perror("socket failed");
            exit(EXIT_FAILURE);
        }

        // set master socket to allow multiple connections ,
        // this is just a good habit, it will work without this
        if (setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt,
                       sizeof(opt)) < 0)
        {
            perror("setsockopt");
            exit(EXIT_FAILURE);
        }

        // type of socket created
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);
        // bind the socket to localhost port 8888
        if (bind(master_socket, (struct sockaddr *)&address, sizeof(address)) < 0)
        {
            perror("bind failed");
            exit(EXIT_FAILURE);
        }
        printf("Listener on port %d \n", port);

        // try to specify maximum of max_clients pending connections for the master socket
        if (listen(master_socket, max_clients) < 0)
        {
            perror("listen");
            exit(EXIT_FAILURE);
        }

        // accept the incoming connection
        addrlen = sizeof(address);
        puts("Waiting for connections ...");

        while (TRUE)
        {
            // clear the socket set
            FD_ZERO(&readfds);

            // add master socket to set
            FD_SET(master_socket, &readfds);
            max_sd = master_socket;

            // add child sockets to set
            for (i = 0; i < max_clients; i++)
            {
                // socket descriptor
                sd = client_sockets[i].sd;

                // if valid socket descriptor then add to read list
                if (sd > 0 && client_sockets[i].in_use)
                    FD_SET(sd, &readfds);

                // highest file descriptor number, need it for the select function
                if (sd > max_sd)
                    max_sd = sd;
            }

            // wait for an activity on one of the sockets , timeout is NULL ,
            // so wait indefinitely
            activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

            if ((activity < 0) && (errno != EINTR))
            {
                printf("select error");
            }

            // If something happened on the master socket ,
            // then its an incoming connection
            if (FD_ISSET(master_socket, &readfds))
            {
                if ((new_socket = accept(master_socket,
                                         (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
                {
                    perror("accept");
                    exit(EXIT_FAILURE);
                }

                // inform user of socket number - used in send and receive commands
                printf("New connection , socket fd is %d , ip is : %s , port : %d \n ", new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));

                // send new connection greeting message
                if (send(new_socket, message, strlen(message), 0) != strlen(message))
                {
                    perror("send");
                }

                puts("Welcome message sent successfully");

                // add new socket to array of sockets
                for (i = 0; i < max_clients; i++)
                {
                    // if position is empty
                    if (client_sockets[i].in_use == false)
                    {
                        client_sockets[i].sd = new_socket;
                        client_sockets[i].in_use = true;
                        printf("Adding to list of sockets as %d on %d\n", new_socket, i);

                        break;
                    }
                }
            }

            // else its some IO operation on some other socket
            for (i = 0; i < max_clients; i++)
            {
                sd = client_sockets[i].sd;

                if (FD_ISSET(sd, &readfds))
                {
                    // establish session key
                    if (client_sockets[i].session_key.empty() && client_sockets[i].exchange_keys(convertToEVP(private_key)) <= 0)
                    {
                        printf("Failed to Exchange Keys with client on ip %s , port %d \n",
                               inet_ntoa(address.sin_addr), ntohs(address.sin_port));
                        onClientDisconnect(&client_sockets[i]);
                    }
                    else if (client_sockets[i].in_use)
                    {
                        int ret = 0;

                        unsigned int command_len = 0;
                        unsigned char *command = recieveAndDecryptMsg(sd, &command_len, (unsigned char *)client_sockets[i].session_key.c_str());
                        if (command == NULL)
                        {
                            onClientDisconnect(&client_sockets[i]);
                            free(command);
                            continue;
                        }
                        string command_str((char *)command, command_len);
                        cout << "command Received: " << command_str << endl;

                        vector<string> args = split(command_str, ':');
                        switch (resolveCommand(args[0]))
                        {
                        case Commands::Login:
                            /* code */
                            onLogin(args, &client_sockets[i]);
                            break;
                        case Commands::Balance:
                            if (!checkUserIsAuthenticated(&client_sockets[i]))
                                continue;
                            onBalance(args, client_sockets[i]);
                            break;
                        case Commands::List:
                            if (!checkUserIsAuthenticated(&client_sockets[i]))
                                continue;
                            onList(args, client_sockets[i]);
                            break;
                        case Commands::Transfer:
                            if (!checkUserIsAuthenticated(&client_sockets[i]))
                                continue;
                            onTransfer(args, client_sockets[i]);
                            break;

                        default:
                            cerr << "No Command Handler Try Again." << command;

                            break;
                        }
                    }
                }
            }
        }
    }
};

int main(int argc, char *argv[])
{
    Server serv;
    cout << "Starting server...\n";
    serv.start_server();
    cout << "Exsiting...\n";

    return 0;
}
