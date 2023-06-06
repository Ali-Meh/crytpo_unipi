#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <cstring> // For memcpy
#include <iostream>
#include "./EC.cpp"

class Client
{
public:
    Client(EVP_PKEY *server_pub_key)
    {
        // Generate Elliptic Curve Diffie-Hellman key pair
        ec_key = generateECDHEVP_PKEY();

        // Save our own public key
        pub_key = getPubKey(ec_key);

        // Print the public key in hexadecimal format
        printECDH("Client pub_key: ", pub_key);

        // Generate shared secret
        size_t secret_length = 0;
        unsigned char *shared_secret = deriveSharedKey(ec_key, server_pub_key, &secret_length);
        std::cout << "Client shared Secret: ";
        for (int i = 0; i < secret_length; i++)
        {
            printf("%02x", shared_secret[i]);
        }
        std::cout << std::endl;
    }

    ~Client()
    {
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(ec_key);
    }

    EVP_PKEY *pub_key;

private:
    EVP_PKEY *ec_key;
};

class Server
{
public:
    Server()
    {
        // Generate Elliptic Curve Diffie-Hellman key pair
        ec_key = generateECDHEVP_PKEY();

        // Save our own public key
        pub_key = getPubKey(ec_key);

        // Print the public key in hexadecimal format
        printECDH("Server pub_key: ", pub_key);
    }

    ~Server()
    {
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(ec_key);
    }

    void calculateSK(EVP_PKEY *peer_pubkey)
    {
        // Generate shared secret
        size_t secret_length = 0;
        unsigned char *shared_secret = deriveSharedKey(ec_key, peer_pubkey, &secret_length);

        std::cout << "Server shared Secret: ";
        for (int i = 0; i < secret_length; i++)
        {
            printf("%02x", shared_secret[i]);
        }
        std::cout << std::endl;
    }

    EVP_PKEY *pub_key;

private:
    EVP_PKEY *ec_key;
};

int main()
{
    Server s;
    Client c(s.pub_key);

    s.calculateSK(c.pub_key);

    return 0;
}
