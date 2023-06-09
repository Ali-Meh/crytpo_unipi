#include <iomanip>
#include <vector>
#include <sstream>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/err.h>
#include <cstring>
#include "const.h"
namespace crypter
{
#include "AES.cpp"
}

using namespace std;

// create custom split() function
vector<string> split(string str, char del)
{
    vector<string> splitted;
    stringstream ss(str);
    string item;
    while (getline(ss, item, del))
    {
        splitted.push_back(item);
    }

    return splitted;
}

enum Commands
{
    Login,
    Balance,
    Transfer,
    List,
    NotValidCommand
};
Commands resolveCommand(string input)
{
    if (input == "0" || input == "login")
        return Commands::Login;
    if (input == "1" || input == "balance")
        return Commands::Balance;
    if (input == "2" || input == "transfer")
        return Commands::Transfer;
    if (input == "3" || input == "list")
        return Commands::List;
    return Commands::NotValidCommand;
}
string ToString(Commands v)
{
    switch (v)
    {
    case Login:
        return "0";
    case Balance:
        return "1";
    case Transfer:
        return "2";
    case List:
        return "3";
    default:
        return "NotValidCommand";
    }
}

enum Errors
{
    Null,
    Todo,
    NotFound,
    NotAuthorized,
    WrongCredentials,
    NotEnoughFunds,
    NotValid
};
Errors resolveError(string input)
{
    if (input == "0" || input == "Todo")
        return Errors::Todo;
    if (input == "1" || input == "NotFound")
        return Errors::NotFound;
    if (input == "2" || input == "NotAuthorized")
        return Errors::NotAuthorized;
    if (input == "3" || input == "WrongCredentials")
        return Errors::WrongCredentials;
    if (input == "4" || input == "NotEnoughFunds")
        return Errors::NotEnoughFunds;

    return Errors::NotValid;
}
enum Response
{
    ERROR,
    SUCCESS
};
Response resolveResponse(string input)
{
    vector<string> parts = split(input, ':');

    if (parts[0] == "0" || parts[0] == "ERROR")
        return Response::ERROR;
    // if (parts[0] == "1" || parts[0] == "SUCCESS")
    return Response::SUCCESS;
}
string generateResult(Errors err, string msg = "")
{

    string res;
    if (err != Errors::Null)
        // Error
        res = "0:" + to_string(static_cast<int>(err)) + ":" + msg;
    else
        // success
        res = "1:" + msg;

    return res;
}

// bin_to_hex
string bin_to_hex(unsigned char *digest, int digest_len)
{
    stringstream hashed_password_stream;
    hashed_password_stream << hex << setfill('0');
    for (int i = 0; i < digest_len; i++)
    {
        hashed_password_stream << setw(2) << static_cast<unsigned>(digest[i]);
    }
    return hashed_password_stream.str();
}
string from_hex_string(const string &hex_str)
{
    string result;
    result.reserve(hex_str.size() / 2);
    for (size_t i = 0; i < hex_str.size(); i += 2)
    {
        result.push_back(stoul(hex_str.substr(i, 2), nullptr, 16));
    }
    return result;
}

int sendInt(int socketfd, unsigned int n)
{

    int ret;

    ret = send(socketfd, (char *)&n, sizeof(n), 0);
    if (ret < 0)
    {
        cerr << "Error sending int\n";
        return 0;
    }

    return 1;
}

int readInt(int socketfd, unsigned int *n)
{

    int ret;

    ret = read(socketfd, (char *)n, sizeof(unsigned int));
    if (ret < 0)
    {
        cerr << "Error reading int\n";
        return 0;
    }

    return 1;
}

int sendMessageWithSize(int sd, unsigned char *message, int messageLength)
{
    int ret;

    ret = sendInt(sd, messageLength);
    if (!ret)
    {
        cerr << "Error writing message total size\n";
        return 0;
    }
    ret = send(sd, message, messageLength, 0);
    if (!ret)
    {
        cerr << "Error writing message\n";
        return 0;
    }

    return 1;
}
int encryptAndSendmsg(int sd, unsigned char *message, int messageLength, unsigned char *key)
{
    int cipher_len = 0;
    unsigned char *cipher = crypter::encryptAES(message, messageLength, &cipher_len, key);
    int ret = sendMessageWithSize(sd, cipher, cipher_len);
    if (PRINT_MESSAGES)
        cout << "<< Sending Message: " << bin_to_hex(message, messageLength) << endl;
    if (PRINT_ENCRYPT_MESSAGES)
        cout << "<< Encrypted(Hex): " << bin_to_hex(cipher, cipher_len) << endl;
    return cipher_len;
}
int sendMessageWithSize(int sd, string message)
{
    int ret;
    int msgLength = message.size();
    ret = sendInt(sd, msgLength);
    if (!ret)
    {
        cerr << "Error writing message total size\n";
        return 0;
    }
    ret = send(sd, message.c_str(), msgLength, 0);
    if (!ret)
    {
        cerr << "Error writing message\n";
        return 0;
    }

    return 1;
}

unsigned char *recieveSizedMessage(int sd, unsigned int *totalSizePtr)
{
    // Read message size
    int ret = readInt(sd, totalSizePtr);
    if (!ret)
    {
        cerr << "Error reading message total size\n";
        return NULL;
    }
    unsigned char *message = (unsigned char *)malloc(*totalSizePtr);

    ret = read(sd, message, *totalSizePtr);
    if (!ret)
    {
        cerr << "Error reading message\n";
        return NULL;
    }

    return message;
}

unsigned char *recieveAndDecryptMsg(int sd, unsigned int *message_len, unsigned char *key)
{
    unsigned int cipher_len = 0;
    unsigned char *cipher = recieveSizedMessage(sd, &cipher_len);
    if (cipher == NULL)
    {
        return NULL;
    }
    if (PRINT_MESSAGES)
        cout << ">> Recived cipher: " << bin_to_hex(cipher, cipher_len) << endl;
    unsigned char *message = crypter::decryptAES(cipher, cipher_len, message_len, key);
    if (PRINT_DECRYPT_MESSAGES)
        cout << ">> Decrypted(Hex): " << bin_to_hex(message, *message_len) << endl;
    return message;
}
// Generate a random and fresh nonce
int createNonce(unsigned char *buffer)
{

    int ret;

    // Generate a 16 bytes random number to ensure unpredictability
    unsigned char *randomBuf = (unsigned char *)malloc(RAND_BUFFER_SIZE);
    if (!randomBuf)
    {
        cerr << "Error allocating unsigned buffer for random bytes\n";
        return 0;
    }
    RAND_poll();
    ret = RAND_bytes(randomBuf, RAND_BUFFER_SIZE);
    if (!ret)
    {
        cerr << "Error generating random bytes\n";
        return 0;
    }
    char *random = (char *)malloc(RAND_BUFFER_SIZE);
    if (!random)
    {
        cerr << "Error allocating buffer for random bytes *\n";
        return 0;
    }
    memcpy(random, randomBuf, RAND_BUFFER_SIZE);
    free(randomBuf);

    // Generate a char timestamp to ensure uniqueness
    char *now = (char *)malloc(TIME_BUFFER_SIZE);
    if (!now)
    {
        cerr << "Error allocating buffer for date and time\n";
        return 0;
    }
    time_t currTime;
    tm *currentTime;
    time(&currTime);
    currentTime = localtime(&currTime);
    if (!currentTime)
    {
        cerr << "Error creating pointer containing current time\n";
        return 0;
    }
    ret = strftime(now, TIME_BUFFER_SIZE, "%Y%j%H%M%S", currentTime);
    if (!ret)
    {
        cerr << "Error putting time in a char array\n";
        return 0;
    }

    // Concatenate random number and timestamp
    char *tempNonce = (char *)malloc(RAND_BUFFER_SIZE + TIME_BUFFER_SIZE);
    if (!tempNonce)
    {
        cerr << "Error allocating char buffer for nonce\n";
        return 0;
    }
    bzero(tempNonce, RAND_BUFFER_SIZE + TIME_BUFFER_SIZE);
    memcpy(tempNonce, random, RAND_BUFFER_SIZE);
    free(random);
    strcat(tempNonce, now);
    free(now);
    memcpy(buffer, tempNonce, NONCE_SIZE);
    free(tempNonce);

    return 1;
}

int handleErrors(std::string msg = "")
{
    std::cerr << "Error: " << msg << "\n"
              << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    exit(1);
}