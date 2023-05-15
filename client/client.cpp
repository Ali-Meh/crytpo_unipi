#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 8080
#define MAX_COMMAND_LENGTH 128
#define MAX_FIELD_LENGTH 255
#define MAX_MSG_LENGTH 512

int main(int argc, char *argv[])
{
    int sock = 0;
    struct sockaddr_in serv_addr;

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

    // Loop for sending commands to server
    while (1)
    {
        char command[MAX_COMMAND_LENGTH];
        printf("Enter command (login, balance, or transfer): ");
        fgets(command, MAX_COMMAND_LENGTH, stdin);
        strtok(command, "\n"); // Remove newline character from input

        // Send login command with username and password
        if (strcmp(command, "login") == 0)
        {
            char username[MAX_FIELD_LENGTH], password[MAX_FIELD_LENGTH];
            printf("Enter username: ");
            fgets(username, MAX_FIELD_LENGTH, stdin);
            strtok(username, "\n");
            printf("Enter password: ");
            fgets(password, MAX_FIELD_LENGTH, stdin);
            strtok(password, "\n");

            // Construct login message
            char message[MAX_COMMAND_LENGTH + (2 * MAX_FIELD_LENGTH)];
            sprintf(message, "%s:%s:%s", command, username, password);

            // Send message to server
            send(sock, message, strlen(message), 0);

            // Receive response from server
            char buffer[MAX_COMMAND_LENGTH] = {0};
            read(sock, buffer, MAX_COMMAND_LENGTH);
            printf("%s\n", buffer);
        }

        // Send balance command with username
        else if (strcmp(command, "balance") == 0)
        {
            char username[MAX_FIELD_LENGTH];
            printf("Enter username: ");
            fgets(username, MAX_FIELD_LENGTH, stdin);
            strtok(username, "\n");

            // Construct balance message
            char message[MAX_COMMAND_LENGTH + MAX_FIELD_LENGTH];
            sprintf(message, "%s:%s", command, username);

            // Send message to server
            send(sock, message, strlen(message), 0);

            // Receive response from server
            char buffer[MAX_COMMAND_LENGTH] = {0};
            read(sock, buffer, MAX_COMMAND_LENGTH);
            printf("%s\n", buffer);
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
