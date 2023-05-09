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
