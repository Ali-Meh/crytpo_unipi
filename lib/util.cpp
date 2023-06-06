#include <iomanip>
#include <vector>
#include <sstream>
#include <iostream>
#include <openssl/err.h>
#include "const.h"

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