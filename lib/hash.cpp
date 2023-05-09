#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>
#include <cstring>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include "util.cpp"

using namespace std;

const int SALT_SIZE = 16;

string generate_salt(int salt_size = SALT_SIZE)
{
    string salt(salt_size, 0);
    RAND_bytes((unsigned char *)salt.data(), salt_size);
    return salt;
}
string hash_password(const string &password)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    string salt = generate_salt();
    stringstream hashed_password_stream;

    // Hash the password with the salt
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, salt.data(), salt.size());
    EVP_DigestUpdate(ctx, password.data(), password.size());
    EVP_DigestFinal_ex(ctx, digest, &digest_len);

    EVP_MD_CTX_free(ctx);
    return bin_to_hex((unsigned char *)salt.c_str(), salt.size()) + ":" + bin_to_hex(digest, digest_len);
}

bool verify_password(const string &input, const string &current)
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    vector<string> splitted = split(current, ':');
    string salt = from_hex_string(splitted[0]);
    string hashed_password = splitted[1];

    // Hash the password with the salt
    EVP_DigestInit_ex(context, md, NULL);
    EVP_DigestUpdate(context, salt.data(), salt.size());
    EVP_DigestUpdate(context, input.data(), input.size());
    EVP_DigestFinal_ex(context, digest, &digest_len);

    // Compare the hashed password with the stored hash
    bool result = (hashed_password == bin_to_hex(digest, digest_len));
    EVP_MD_CTX_free(context);
    return result;
}

// int main()
// {
//     // Hash a password and store it
//     string hashed_password = hash_password("password1123");

//     // Split the hashed password into salt and hash
//     vector<string> splitted = split(hashed_password, ':');
//     string salt = splitted[0];
//     string stored_hash = splitted[1];

//     // Verify a password
//     // string input_password;
//     // cout << "Enter password: ";
//     // cin >> input_password;

//     cout << "password hash=> " << hashed_password << endl;
//     bool r = verify_password("input_password", hashed_password);
//     cout << r << endl;

//     r = verify_password("password1123", hashed_password);
//     cout << r << endl;

//     // if (verify_password(input_password, hashed_password))
//     // {
//     //     cout << "Password is correct!" << endl;
//     // }
//     // else
//     // {
//     //     cout << "Incorrect password." << endl;
//     // }

//     return 0;
// }
