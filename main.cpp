#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <cstring> // For memcpy
#include <iostream>
#include "./lib/dh.cpp"
using namespace std;

// int handleErrors(string msg = "")
// {
//     std::cerr << "Error: " << msg << "\n"
//               << ERR_error_string(ERR_get_error(), nullptr) << '\n';
//     exit(1);
// }
// unsigned char *deriveSharedKey(EVP_PKEY *dh_key, EVP_PKEY *peer_pubkey, size_t *skey_len)
// {

//     // Generate shared secret
//     EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(dh_key, NULL);
//     EVP_PKEY_derive_init(ctx);
//     EVP_PKEY_derive_set_peer(ctx, peer_pubkey);

//     /* Determine buffer length, by performing a derivation but writing the result nowhere */
//     size_t secret_length = 0;
//     unsigned char *shared_secret = NULL;
//     EVP_PKEY_derive(ctx, NULL, &secret_length);
//     shared_secret = (unsigned char *)malloc(secret_length);
//     EVP_PKEY_derive(ctx, shared_secret, &secret_length);

//     // Use shared secret to derive symmetric encryption key
//     // Here we're using a hash of the shared secret
//     unsigned char md_value[EVP_MAX_MD_SIZE];
//     unsigned int md_len = 0;
//     EVP_Digest(shared_secret, secret_length, md_value, &md_len, EVP_sha256(), NULL);
//     *skey_len = 32;
//     unsigned char *sk = (unsigned char *)(malloc(*skey_len));
//     memcpy(sk, md_value, *skey_len); // Use the first 32 bytes as the key

//     EVP_PKEY_CTX_free(ctx);
//     free(shared_secret);
//     return sk;
// }

class Client
{
public:
    Client()
    {
        // Generate Diffie-Hellman parameters and generate public/private keys
        dh_params = DH_new();
        DH_generate_parameters_ex(dh_params, 2048, DH_GENERATOR_2, NULL);
        DH_generate_key(dh_params);

        // Save our own public key and Diffie-Hellman parameters
        pub_key = EVP_PKEY_new();
        EVP_PKEY_set1_DH(pub_key, dh_params);
        // pub_key = evp_dh(pkey);
        std::cout << "Client pub_key: " << BN_bn2hex(DH_get0_pub_key(dh_params)) << std::endl;
    }

    ~Client()
    {
        EVP_PKEY_free(pub_key);
        DH_free(dh_params);
    }

    // Send our public key and Diffie-Hellman parameters to server
    void send_params()
    {
        // Pseudo-implementation - actual sending would depend on your network setup
        // server->receive_params(pub_key, dh_params);
    }

    // Receive server's public key
    void receive_key(EVP_PKEY *server_key)
    {
        size_t secret_length = 0;
        // unsigned char shared_secret[32] = {0};
        unsigned char *sk = deriveSharedKey(pub_key, server_key, &secret_length);
        std::cout << "client shared Secret: ";
        for (int i = 0; i < secret_length; i++)
        {
            printf("%02x", sk[i]);
        }
        std::cout << std::endl;

        // // Generate shared secret
        // EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, NULL);
        // EVP_PKEY_derive_init(ctx);
        // EVP_PKEY_derive_set_peer(ctx, server_key);

        // size_t secret_length = 0;
        // unsigned char *shared_secret = NULL;
        // EVP_PKEY_derive(ctx, NULL, &secret_length);
        // shared_secret = (unsigned char *)malloc(secret_length);
        // EVP_PKEY_derive(ctx, shared_secret, &secret_length);

        // // Use shared secret to derive symmetric encryption key
        // // Here we're using a hash of the shared secret
        // unsigned char md_value[EVP_MAX_MD_SIZE];
        // unsigned int md_len = 0;
        // EVP_Digest(shared_secret, secret_length, md_value, &md_len, EVP_sha256(), NULL);
        // memcpy(sym_key, md_value, 32); // Use the first 32 bytes as the key

        // std::cout << "client shared Secret: ";
        // for (int i = 0; i < 32; i++)
        // {
        //     printf("%02x", sym_key[i]);
        // }
        // std::cout << std::endl;

        // EVP_PKEY_CTX_free(ctx);
        // free(shared_secret);
    }

    EVP_PKEY *pub_key;
    DH *dh_params;

private:
    unsigned char sym_key[32] = {0};
};

class Server
{
public:
    Server()
    {
    }

    ~Server()
    {
        EVP_PKEY_free(pub_key);
        DH_free(dh_params);
    }

    // Receive client's public key and Diffie-Hellman parameters
    void receive_params(EVP_PKEY *client_key, DH *client_params)
    {
        // Server should use the client's DH parameters, but generate its own keys
        dh_params = DHparams_dup(client_params);
        // dh_params = client_params;
        if (DH_generate_key(dh_params) != 1)
        {
            std::cout << "Error generating server's key pair" << std::endl;
            return;
        }

        // Save our own public key
        pub_key = EVP_PKEY_new();
        EVP_PKEY_set1_DH(pub_key, dh_params);
        std::cout << "Server pub_key: " << BN_bn2hex(DH_get0_pub_key(dh_params)) << std::endl;

        size_t secret_length = 0;
        unsigned char *shared_secret = deriveSharedKey(pub_key, client_key, &secret_length);
        std::cout << "server shared Secret: ";
        for (int i = 0; i < secret_length; i++)
        {
            printf("%02x", shared_secret[i]);
        }
        std::cout << std::endl;

        // // Generate shared secret
        // EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, NULL);
        // EVP_PKEY_derive_init(ctx);
        // EVP_PKEY_derive_set_peer(ctx, client_key);

        // size_t secret_length;
        // unsigned char *shared_secret = NULL;
        // EVP_PKEY_derive(ctx, NULL, &secret_length);
        // shared_secret = (unsigned char *)malloc(secret_length);
        // EVP_PKEY_derive(ctx, shared_secret, &secret_length);

        // // Use shared secret to derive symmetric encryption key
        // // Here we're using a hash of the shared secret
        // unsigned char md_value[EVP_MAX_MD_SIZE];
        // unsigned int md_len;
        // EVP_Digest(shared_secret, secret_length, md_value, &md_len, EVP_sha256(), NULL);
        // memcpy(sym_key, md_value, 32); // Use the first 32 bytes as the key

        // std::cout << "server shared Secret: ";
        // for (int i = 0; i < 32; i++)
        // {
        //     printf("%02x", sym_key[i]);
        // }
        // std::cout << std::endl;

        // EVP_PKEY_CTX_free(ctx);
        // free(shared_secret);

        // EVP_PKEY_free(pub_key);
    }

    EVP_PKEY *pub_key;

private:
    DH *dh_params;
    unsigned char sym_key[32];
};

int main()
{
    Client c;
    Server s;

    s.receive_params(c.pub_key, c.dh_params);
    c.receive_key(s.pub_key);
}
