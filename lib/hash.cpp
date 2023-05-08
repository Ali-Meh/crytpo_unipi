#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>
#include <cstring>
#include <iostream>
#include "util.cpp"

using namespace std;

const int SALT_SIZE = 16;

// class Password
// {
// public:
//     Password() : salt_size(16) {}
//     Password(const string &password, int salt_size = 16) : salt_size(salt_size)
//     {
//         salt = generate_salt();
//         hash_password(password);
//     }

//     void hash_password(const string &password)
//     {
//         EVP_MD_CTX *ctx = EVP_MD_CTX_new();
//         const EVP_MD *md = EVP_sha256();
//         unsigned char digest[EVP_MAX_MD_SIZE];
//         unsigned int digest_len;

//         // Hash the password with the salt
//         EVP_DigestInit_ex(ctx, md, NULL);
//         EVP_DigestUpdate(ctx, salt.data(), salt_size);
//         EVP_DigestUpdate(ctx, password.data(), password.size());
//         EVP_DigestFinal_ex(ctx, digest, &digest_len);

//         // Store the hashed password
//         hashed_password.assign((const char *)digest, digest_len);
//         EVP_MD_CTX_free(ctx);
//     }

//     bool verify_password(const string &password) const
//     {
//         EVP_MD_CTX *context = EVP_MD_CTX_new();
//         const EVP_MD *md = EVP_sha256();
//         unsigned char digest[EVP_MAX_MD_SIZE];
//         unsigned int digest_len;

//         // Hash the password with the salt
//         EVP_DigestInit_ex(context, md, NULL);
//         EVP_DigestUpdate(context, salt.data(), salt_size);
//         EVP_DigestUpdate(context, password.data(), password.size());
//         EVP_DigestFinal_ex(context, digest, &digest_len);

//         // Compare the hashed password with the stored hash
//         bool result = (hashed_password == string((const char *)digest, digest_len));
//         EVP_MD_CTX_free(context);
//         return result;
//     }

//     string get_hashed_password() const
//     {
//         return hashed_password;
//     }

//     string get_salt() const
//     {
//         return salt;
//     }

//     // Override string to embed salt
//     operator string() const
//     {
//         return salt + ":" + hashed_password;
//     }

// private:
//     string generate_salt()
//     {
//         string salt(salt_size, 0);
//         RAND_bytes((unsigned char *)salt.data(), salt_size);
//         return salt;
//     }

//     string hashed_password;
//     string salt;
//     int salt_size;
// };

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
    string hashed_password;

    // Hash the password with the salt
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, salt.data(), salt.size());
    EVP_DigestUpdate(ctx, password.data(), password.size());
    EVP_DigestFinal_ex(ctx, digest, &digest_len);

    // Store the hashed password
    hashed_password = std::string((const char *)digest, digest_len);

    EVP_MD_CTX_free(ctx);
    return string_to_hex(salt) + ":" + string_to_hex(hashed_password);
}

int main()
{
    // Password p("password123");
    // string salt = p.get_salt();
    string hashed_password = hash_password("password1231");
    vector<string> splited = split(hashed_password, ":");
    cout << "=> " << hashed_password << endl;
    cout << "Salt=> " << splited[0] << endl;
    cout << "Hashed password=> " << splited[1] << endl;

    // // Verify the password
    // bool result = p.verify_password("password123");
    // cout << "Password verification result: " << result << endl;

    // // Override string to embed salt
    // string password_str = p;
    // cout << "Password string: " << password_str << endl;
}