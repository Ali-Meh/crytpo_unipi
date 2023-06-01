#include <iomanip>
#include <vector>
#include <sstream>
#include <iostream>

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

int recieveSizedMessage(int sd, unsigned char *message)
{
    // Read message size
    unsigned int *totalSizePtr = (unsigned int *)malloc(sizeof(unsigned int));
    int ret = readInt(sd, totalSizePtr);
    if (!ret)
    {
        cerr << "Error reading message total size\n";
        return 0;
    }
    unsigned int messageLength = *totalSizePtr;
    free(totalSizePtr);

    ret = read(sd, message, messageLength);
    if (!ret)
    {
        cerr << "Error reading message\n";
        return 0;
    }

    return 1;
}