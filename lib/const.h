// Symmetric cipher constants
#define AES_KEY_SIZE 32
#define HMAC_SIZE 32
// #define blockSize 16
#define ivSize 16

#define BUFFER_SIZE 1025

#define TRANSACTION_LIMIT 10

// Authentication constants
#define RAND_BUFFER_SIZE 16
#define TIME_BUFFER_SIZE 64
#define NONCE_SIZE 29

#define SERVER_PORT 8080
#define SERVER_ADDR "127.0.0.1"

#define TRUE 1
#define FALSE 0

// Client
#define MAX_COMMAND_LENGTH 128
#define MAX_FIELD_LENGTH 255
#define MAX_MSG_LENGTH 1024

// Verbose
#define PRINT_ENCRYPT_MESSAGES FALSE
#define PRINT_DECRYPT_MESSAGES TRUE
#define PRINT_MESSAGES TRUE
