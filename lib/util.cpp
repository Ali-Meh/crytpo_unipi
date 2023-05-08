#include <iostream>
#include <string>
#include <vector>
using namespace std;

// create custom split() function
vector<string> split(string str, string del)
{
    vector<string> s;
    // Use find function to find 1st position of delimiter.
    int end = str.find(del);
    while (end != -1)
    { // Loop until no delimiter is left in the string.
        s.push_back(str.substr(0, end));
        str.erase(str.begin(), str.begin() + end + 1);
        end = str.find(del);
    }
    s.push_back(str.substr(0, end));

    return s;
}

#include <string>
#include <sstream>

// Convert a string to hex
std::string string_to_hex(const std::string &input)
{
    static const char *const lut = "0123456789abcdef";
    size_t len = input.length();

    std::string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}

// Convert hex to a string
std::string hex_to_string(const std::string &input)
{
    static const char *const lut = "0123456789abcdef";
    size_t len = input.length();

    if (len & 1)
        throw std::invalid_argument("Odd length");

    std::string output;
    output.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2)
    {
        char a = input[i];
        const char *p = std::lower_bound(lut, lut + 16, a);
        if (*p != a)
            throw std::invalid_argument("Not a hex digit");

        char b = input[i + 1];
        const char *q = std::lower_bound(lut, lut + 16, b);
        if (*q != b)
            throw std::invalid_argument("Not a hex digit");

        output.push_back(((p - lut) << 4) | (q - lut));
    }
    return output;
}

// uses overloaded '=' operator from string class
// to convert character array to string
string convertToString(char *a)
{
    string s = a;
    return s;
}

inline char binary_to_hex_digit(unsigned a)
{
    return a + (a < 10 ? '0' : 'a' - 10);
}
std::string binary_to_hex(unsigned char const *binary, unsigned binary_len)
{
    std::string r(binary_len * 2, '\0');
    for (unsigned i = 0; i < binary_len; ++i)
    {
        r[i * 2] = binary_to_hex_digit(binary[i] >> 4);
        r[i * 2 + 1] = binary_to_hex_digit(binary[i] & 15);
    }
    return r;
}