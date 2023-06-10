#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>
#include <cstring>
#include <iostream>
#include <vector>
#include <sstream>
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

unsigned char *sha256(unsigned char *input, int input_length, unsigned char *digest, unsigned int *digest_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();

    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, input, input_length);
    EVP_DigestFinal_ex(ctx, digest, digest_len);
    EVP_MD_CTX_free(ctx);

    return digest;
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
