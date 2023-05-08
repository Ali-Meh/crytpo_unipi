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

// // Convert a string to hex
// std::string string_to_hex(const std::string &input)
// {
//     static const char *const lut = "0123456789abcdef";
//     size_t len = input.length();

//     std::string output;
//     output.reserve(2 * len);
//     for (size_t i = 0; i < len; ++i)
//     {
//         const unsigned char c = input[i];
//         output.push_back(lut[c >> 4]);
//         output.push_back(lut[c & 15]);
//     }
//     return output;
// }

// // Convert hex to a string
// std::string hex_to_string(const std::string &input)
// {
//     static const char *const lut = "0123456789abcdef";
//     size_t len = input.length();

//     if (len & 1)
//         throw std::invalid_argument("Odd length");

//     std::string output;
//     output.reserve(len / 2);
//     for (size_t i = 0; i < len; i += 2)
//     {
//         char a = input[i];
//         const char *p = std::lower_bound(lut, lut + 16, a);
//         if (*p != a)
//             throw std::invalid_argument("Not a hex digit");

//         char b = input[i + 1];
//         const char *q = std::lower_bound(lut, lut + 16, b);
//         if (*q != b)
//             throw std::invalid_argument("Not a hex digit");

//         output.push_back(((p - lut) << 4) | (q - lut));
//     }
//     return output;
// }

// // uses overloaded '=' operator from string class
// // to convert character array to string
// string convertToString(char *a)
// {
//     string s = a;
//     return s;
// }

// // inline char binary_to_hex_digit(unsigned a)
// // {
// //     return a + (a < 10 ? '0' : 'a' - 10);
// // }
// // std::string binary_to_hex(unsigned char const *binary, unsigned binary_len)
// // {
// //     std::string r(binary_len * 2, '\0');
// //     for (unsigned i = 0; i < binary_len; ++i)
// //     {
// //         r[i * 2] = binary_to_hex_digit(binary[i] >> 4);
// //         r[i * 2 + 1] = binary_to_hex_digit(binary[i] & 15);
// //     }
// //     return r;
// // }

// string hex_to_binary(const string &s)
// {
//     string out;
//     for (auto i : s)
//     {
//         uint8_t n;
//         if (i <= '9' and i >= '0')
//             n = i - '0';
//         else
//             n = 10 + i - 'A';
//         for (int8_t j = 3; j >= 0; --j)
//             out.push_back((n & (1 << j)) ? '1' : '0');
//     }

//     return out;
// }

// string binary_to_hex(const string &s)
// {
//     string out;
//     for (uint i = 0; i < s.size(); i += 4)
//     {
//         int8_t n = 0;
//         for (uint j = i; j < i + 4; ++j)
//         {
//             n <<= 1;
//             if (s[j] == '1')
//                 n |= 1;
//         }

//         if (n <= 9)
//             out.push_back('0' + n);
//         else
//             out.push_back('A' + n - 10);
//     }

//     return out;
// }