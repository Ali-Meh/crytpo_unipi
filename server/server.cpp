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

using namespace std;

#define TRUE 1
#define FALSE 0
#define PORT 8080

/* Structure describing an Internet socket address.  */
struct sba_client_conn
{
    bool in_use;
    int sd;             /*Socket Descriptor*/
    string session_key; /*Session key for secure connection*/
    int valid_until;    /*Session key validity period*/
};

void close_and_free_socket(sba_client_conn client_socket)
{
    // Close the socket and mark as 0 in list for reuse
    close(client_socket.sd);
    client_socket.in_use = false;
    client_socket.sd = 0;
}

int main(int argc, char *argv[])
{
    int opt = TRUE;
    int master_socket, addrlen, new_socket, max_clients = 30, activity, i, valread, sd;
    int max_sd;
    sqlite3 *db = connect("../SBA.db");
    struct sockaddr_in address;
    sba_client_conn client_socket[30];

    char buffer[1025]; // data buffer of 1K

    // set of socket descriptors
    fd_set readfds;

    // a message
    char *message = (char *)"Welcome to SBA server v1.0 \r\n";

    // initialise all client_socket[] to 0 so not checked
    for (i = 0; i < max_clients; i++)
    {
        client_socket[i].in_use = false;
        client_socket[i].sd = 0;
    }

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
    address.sin_port = htons(PORT);

    // bind the socket to localhost port 8888
    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    printf("Listener on port %d \n", PORT);

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
            sd = client_socket[i].sd;

            // if valid socket descriptor then add to read list
            if (sd > 0 && client_socket[i].in_use)
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
                if (client_socket[i].in_use == false)
                {
                    client_socket[i].sd = new_socket;
                    client_socket[i].in_use = true;
                    printf("Adding to list of sockets as %d\n", i);

                    break;
                }
            }
        }

        // else its some IO operation on some other socket
        for (i = 0; i < max_clients; i++)
        {
            sd = client_socket[i].sd;

            if (FD_ISSET(sd, &readfds))
            {
                // Check if it was for closing , and also read the
                // incoming message
                if ((valread = read(sd, buffer, 1024)) == 0)
                {
                    // Somebody disconnected , get his details and print
                    getpeername(sd, (struct sockaddr *)&address,
                                (socklen_t *)&addrlen);
                    printf("Host disconnected , ip %s , port %d \n",
                           inet_ntoa(address.sin_addr), ntohs(address.sin_port));

                    // Close the socket and mark as 0 in list for reuse
                    close_and_free_socket(client_socket[i]);
                }

                // Echo back the message that came in
                else
                {
                    // set the string terminating NULL byte on the end
                    // of the data read
                    // buffer[valread] = '\0';
                    // Parse the message
                    string message(buffer, valread);
                    // printf("Message: %s\n", message);

                    if (client_socket[i].session_key.empty())
                    { // it's login request decrypt via pub/prv keys
                        string decrypted = decryptPrvRSA(message, "../prv.pem");
                        printf("command Received: %s\n\r", decrypted.c_str());
                        vector<string> parts = split(decrypted, ':');
                        if (strcmp(parts[0].c_str(), "login") != 0)
                        {
                            sprintf(buffer, "ERROR: %s\0", "unathorized!");
                            send(sd, buffer, 0, 0);
                            close_and_free_socket(client_socket[i]);
                        }

                        vector<sba_client_t> db_users = getClientByUsername(db, parts[1]);
                        printf("found user id %d\n", db_users[0].id);
                        if (db_users.empty() || !verify_password(parts[2], db_users[0].password))
                        {
                            sprintf(buffer, "ERROR: %s\0", "unathorized!");
                            printf("wrote %d bytes to buffer, %s\n", strlen(buffer), buffer);
                            send(sd, buffer, strlen(buffer), 0);
                            close_and_free_socket(client_socket[i]);
                        }
                        else
                        {
                            // generate session key
                            client_socket[i].session_key = generate_aes_key();
                            // encrypt with users pubkey
                            sprintf(buffer, "SET_SESSION_KEY:%s\0", client_socket[i].session_key.data());

                            printf("SET_SESSION_KEY:%s\n\r\0", bin_to_hex((unsigned char *)client_socket[i].session_key.data(), client_socket[i].session_key.size()).data());
                            string msg = encryptPubRSA(buffer, db_users[0].pubkey);
                            printf("session: %s\n", bin_to_hex((unsigned char *)msg.data(), msg.size()).data());
                            // send it over to user to use
                            send(sd, msg.c_str(), msg.size(), 0);
                        }
                    }
                    else
                    { // it's symetric key decrypt via session key
                      // decrypt the payload recived
                        string decrypted(decrypt_data(buffer, valread, (char *)client_socket[i].session_key.data()), valread);
                        printf("%s: %s\n", decrypted, bin_to_hex((unsigned char *)buffer, valread).data());
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
                                char *payload = encrypt_data(buffer, strlen(buffer), (char *)client_socket[i].session_key.data());
                                send(sd, payload, strlen(payload), 0);
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

    return 0;
}
