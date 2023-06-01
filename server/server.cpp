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
#include "../lib/RSA.cpp"  //Code for processing [a]symectric encryptions
#include "../lib/db.cpp"   //Code for processing db
#include "../lib/hash.cpp" //Code for processing hashing
#include "../lib/AES.cpp"  //Code for processing symectric encryptions
#include "../lib/const.h"  //Code for processing symectric encryptions

using namespace std;

/* Structure describing an Internet socket address.  */
struct sba_client_conn
{
    bool in_use;
    int sd;             /*Socket Descriptor*/
    string session_key; /*Session key for secure connection*/
    int valid_until;    /*Session key validity period*/
};

class Server
{
    int opt = TRUE;
    const static int max_clients = 30;
    int master_socket, addrlen, new_socket, activity, i, valread, sd, max_sd;
    sba_client_conn client_sockets[max_clients];
    // set of socket descriptors
    fd_set readfds;
    sqlite3 *db;
    struct sockaddr_in address;
    char buffer[BUFFER_SIZE]; // data buffer of 1K

    // welcome message
    char *message = (char *)"Welcome to SBA server v1.0 \r\n";
    void close_and_free_socket(sba_client_conn client_socket)
    {
        // Close the socket and mark as 0 in list for reuse
        close(client_socket.sd);
        client_socket.in_use = false;
        client_socket.sd = 0;
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

        // try to specify maximum of 3 pending connections for the master socket
        if (listen(master_socket, 3) < 0)
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
                        printf("Adding to list of sockets as %d\n", i);

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
                    // Check if it was for closing , and also read the
                    // incoming message
                    memset(buffer, '\0', sizeof(buffer));
                    if ((valread = read(sd, buffer, BUFFER_SIZE)) == 0)
                    {
                        // Somebody disconnected , get his details and print
                        getpeername(sd, (struct sockaddr *)&address,
                                    (socklen_t *)&addrlen);
                        printf("Host disconnected , ip %s , port %d \n",
                               inet_ntoa(address.sin_addr), ntohs(address.sin_port));

                        // Close the socket and mark as 0 in list for reuse
                        close_and_free_socket(client_sockets[i]);
                    }

                    // Process Messages
                    else
                    {
                        // set the string terminating NULL byte on the end
                        // of the data read
                        // buffer[valread] = '\0';
                        // Parse the message
                        string message(buffer, valread);
                        // printf("Message: %s\n", message);

                        if (client_sockets[i].session_key.empty())
                        { // it's login request decrypt via pub/prv keys
                            string decrypted = decryptPrvRSA(message, "../prv.pem");
                            printf("command Received: %s\n\r", decrypted.c_str());
                            vector<string> parts = split(decrypted, ':');
                            if (strcmp(parts[0].c_str(), "login") != 0)
                            {
                                sprintf(buffer, "ERROR: %s\0", "unathorized!");
                                send(sd, buffer, 0, 0);
                                close_and_free_socket(client_sockets[i]);
                            }

                            vector<sba_client_t> db_users = getClientByUsername(db, parts[1]);
                            printf("found user id %d\n", db_users[0].id);
                            if (db_users.empty() || !verify_password(parts[2], db_users[0].password))
                            {
                                sprintf(buffer, "ERROR: %s\0", "unathorized!");
                                printf("wrote %d bytes to buffer, %s\n", strlen(buffer), buffer);
                                send(sd, buffer, strlen(buffer), 0);
                                close_and_free_socket(client_sockets[i]);
                            }
                            else
                            {
                                // generate session key
                                client_sockets[i].session_key = generate_aes_key();
                                // encrypt with users pubkey
                                sprintf(buffer, "SET_SESSION_KEY:%s\0", bin_to_hex((unsigned char *)client_sockets[i].session_key.data(), client_sockets[i].session_key.size()).data());

                                printf("decrypted session key: -> %s\n", buffer);
                                // for (size_t j = 0; j < 32; ++j)
                                // {
                                //     printf("%02x", client_socket[i].session_key[j]);
                                // }
                                string msg = encryptPubRSA(buffer, db_users[0].pubkey);
                                // printf("session: %s\n", bin_to_hex((unsigned char *)msg.data(), msg.size()).data());
                                // send it over to user to use
                                send(sd, msg.c_str(), msg.size(), 0);
                            }
                        }
                        else
                        { // it's symetric key decrypt via session key
                            // decrypt the payload recived
                            // unsigned char *message = (unsigned char *)malloc(BUFFER_SIZE);
                            // size_t decryptedPlaintextLength = decryptSym((unsigned char *)buffer, valread - ivSize, message, (unsigned char *)client_sockets[i].session_key.data());
                            unsigned char *decodeText = (unsigned char *)malloc(BUFFER_SIZE);
                            size_t decryptedPlaintextLength = decryptSym(reinterpret_cast<unsigned char *>(buffer), valread - ivSize, decodeText, (unsigned char *)client_sockets[i].session_key.data());
                            printf("Decrypted Text: %s\n", (char *)decodeText);

                            string decrypted(*decodeText, decryptedPlaintextLength);
                            printf("decrypted recived aes: %s: %s\n", decodeText, bin_to_hex((unsigned char *)buffer, valread).data());
                            vector<string> parts = split(decrypted, ':');
                            // switch based on the command [0]
                            if (strcmp(parts[0].data(), "balance"))
                            {
                                vector<sba_client_t> db_users = getClientByUsername(db, parts[1]);
                                if (db_users.empty())
                                {
                                    sprintf(buffer, "ERROR: %s\0", "unathorized!");
                                    send(sd, buffer, 0, 0);
                                }
                                else
                                {
                                    printf("found user id %d\n", db_users[0].id);
                                    sprintf(buffer, "BALANCE: %d\0", db_users[0].balance);
                                    unsigned char *payload = (unsigned char *)malloc(BUFFER_SIZE);
                                    size_t ciphertextLength = encryptSym((unsigned char *)buffer, strlen(buffer), payload, (unsigned char *)client_sockets[i].session_key.data());
                                    send(sd, payload, ciphertextLength, 0);
                                }
                            }
                            else if (strcmp(parts[0].data(), "transfer"))
                            {
                                cerr << "TODO:TRANSFER";
                            }
                            else
                            {
                                cerr << "TODO:ELSE";
                            }

                            // encrypt and send back the response
                        }

                        // vector<string> parts = split(message, ':');
                        // printf("%s command Received\n\r", parts[0].c_str());
                        // sprintf(buffer, "%s %s\n", "recived: ", message.c_str());
                        // send(sd, buffer, strlen(buffer) + 10, 0);
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
    cout << "Socket connection established\n";

    return 0;
}
