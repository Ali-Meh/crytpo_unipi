#include <iostream>
#include <cstring>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "const.h"

using namespace std;

int handleErrors(string msg = "")
{
    std::cerr << "Error: " << msg << "\n"
              << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    exit(1);
}
static DH *dh = NULL;

void init()
{
    if (!dh)
    {
        string dh_parmas_path = "../keys/params.pem";

        FILE *p1w = fopen(dh_parmas_path.c_str(), "r+");
        if (!p1w)
        {
            cerr << "Error: cannot write file \n";
            exit(1);
        }
        PEM_read_DHparams(p1w, &dh, NULL, NULL);

        if (!dh)
        {
            dh = DH_new();
            if (!dh)
            {
                handleErrors("Failed to create Diffie-Hellman parameters");
            }

            if (DH_generate_parameters_ex(dh, DH_PARAM_SIZE, DH_GENERATOR_2, NULL) != 1)
            {
                handleErrors("Failed to generate Diffie-Hellman parameters");
            }

            printf("Generated ephemeral DH KeyPair\n");

            PEM_write_DHparams(p1w, dh);
            fclose(p1w);
        }
    }
}

EVP_PKEY *generateKey()
{
    EVP_PKEY *params;
    if (NULL == (params = EVP_PKEY_new()))
        handleErrors();
    init();
    if (1 != EVP_PKEY_set1_DH(params, dh))
        handleErrors();

    /* Create context for the key generation */
    EVP_PKEY_CTX *DHctx;
    if (!(DHctx = EVP_PKEY_CTX_new(params, NULL)))
        handleErrors();
    /* Generate a new key */
    EVP_PKEY *my_dhkey = NULL;
    if (1 != EVP_PKEY_keygen_init(DHctx))
        handleErrors();
    if (1 != EVP_PKEY_keygen(DHctx, &my_dhkey))
        handleErrors();

    return my_dhkey;
}

int saveKey(string file_name, EVP_PKEY *dh_key)
{
    FILE *p1w = fopen(file_name.c_str(), "w");
    if (!p1w)
    {
        cerr << "Error: cannot write to file" << file_name << "\n";
        return 1;
    }
    int ret = PEM_write_PUBKEY(p1w, dh_key);
    fclose(p1w);
    return ret;
}
EVP_PKEY *loadKey(string file_name)
{
    /*Load public key from a file*/
    FILE *p2r = fopen(file_name.c_str(), "r");
    if (!p2r)
    {
        cerr << "Error: cannot open file '" << file_name << "' (missing?)\n";
        return NULL;
    }
    EVP_PKEY *pub_key = PEM_read_PUBKEY(p2r, NULL, NULL, NULL);
    if (!pub_key)
    {
        cerr << "Error: PEM_read_PUBKEY returned NULL\n";
        exit(1);
    }

    fclose(p2r);
    return pub_key;
}

unsigned char *deriveSharedKey(EVP_PKEY *dh_params, EVP_PKEY *peer_pubkey, size_t *skey_len)
{

    /*creating a context, the buffer for the shared key and an int for its length*/
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    if (!ctx)
        handleErrors();
    if (EVP_PKEY_derive_init(ctx) <= 0)
        handleErrors();
    /*Setting the peer with its pubkey*/
    if (EVP_PKEY_derive_set_peer(ctx, peer_pubkey) <= 0)
        handleErrors();
    /* Determine buffer length, by performing a derivation but writing the result nowhere */
    size_t secret_length = 0;
    EVP_PKEY_derive(ctx, NULL, &secret_length);
    unsigned char *shared_secret = (unsigned char *)malloc(secret_length);
    /*Perform again the derivation and store it in skey buffer*/
    if (EVP_PKEY_derive(ctx, shared_secret, &secret_length) <= 0)
        handleErrors();

    // Use shared secret to derive symmetric encryption key
    // Here we're using a hash of the shared secret
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    EVP_Digest(shared_secret, secret_length, md_value, &md_len, EVP_sha256(), NULL);
    *skey_len = 32;
    unsigned char *sk = (unsigned char *)(malloc(*skey_len));
    memcpy(sk, md_value, *skey_len); // Use the first 32 bytes as the key

    EVP_PKEY_CTX_free(ctx);
    free(shared_secret);
    return sk;
}

void print_big_num(const BIGNUM *bobPublicKey)
{
    // Print bobPublicKey
    char *bobPublicKeyHex = BN_bn2hex(bobPublicKey);
    if (bobPublicKeyHex)
    {
        printf("bobPublicKey: %s\n", bobPublicKeyHex);
        OPENSSL_free(bobPublicKeyHex);
    }
    else
    {
        printf("Failed to convert bobPublicKey to hex\n");
    }
}

// int main()
// {
//     init();
//     EVP_PKEY *my_key = generateKey();
//     EVP_PKEY *peer_key = generateKey();

//     FILE *p1w = fopen("my.dh.pem", "w");
//     if (!p1w)
//     {
//         cerr << "Error: cannot open file '"
//              << "my.dh.pem"
//              << "' (missing?)\n";
//         exit(1);
//     }
//     PEM_write_PUBKEY(p1w, my_key);
//     fclose(p1w);

//     // DH *p = EVP_PKEY_get1_DH(my_key);
//     // p1w = fopen("my.params.pem", "w");
//     // if (!p1w)
//     // {
//     //     cerr << "Error: cannot open file '"
//     //          << "my.params.pem"
//     //          << "' (missing?)\n";
//     //     exit(1);
//     // }
//     // PEM_write_DHparams(p1w, p);
//     // fclose(p1w);

//     size_t skeylen = 0;
//     unsigned char *skey = deriveSharedKey(my_key, peer_key, &skeylen);
//     printf("Shared secret derived successfully\n");

//     // Print the shared secret
//     printf("Shared Secret: ");
//     for (size_t i = 0; i < skeylen; i++)
//         printf("%02x", skey[i]);
//     printf("\n");

//     EVP_PKEY_free(my_key);
//     EVP_PKEY_free(peer_key);

//     delete[] skey;
// }
