#include <iostream>
#include <string>
#include <stdio.h>  // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

using namespace std;

// deriveSharedKey for ECDH algorithm and hash the secret generated into sha256 as it's recommended for more security
unsigned char *deriveSharedKey(EVP_PKEY *ec_key, EVP_PKEY *peer_pubkey, size_t *skey_len)
{
    // Generate shared secret
    *skey_len = 32;
    unsigned char *sym_key = (unsigned char *)malloc(*skey_len);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(ec_key, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_pubkey);

    /* Determine buffer length, by performing a derivation but writing the result nowhere */
    size_t secret_length = 0;
    unsigned char *shared_secret = NULL;
    EVP_PKEY_derive(ctx, NULL, &secret_length);
    shared_secret = (unsigned char *)malloc(secret_length);
    EVP_PKEY_derive(ctx, shared_secret, &secret_length);

    // Use shared secret to derive symmetric encryption key
    // Here we're using a hash of the shared secret
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    EVP_Digest(shared_secret, secret_length, md_value, &md_len, EVP_sha256(), NULL);
    memcpy(sym_key, md_value, *skey_len);

    // Clean up
    EVP_PKEY_CTX_free(ctx);
    free(shared_secret);
    return sym_key;
}

// Generate Elliptic Curve Diffie-Hellman key pair
EVP_PKEY *generateECDHKey()
{
    EVP_PKEY *ec_key = EVP_PKEY_new();
    EVP_PKEY_set_type(ec_key, EVP_PKEY_EC);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(ctx, &ec_key);
    EVP_PKEY_CTX_free(ctx);
    return ec_key;
}
EVP_PKEY *getPubKey(EVP_PKEY *ec_key)
{
    EVP_PKEY *pub_key = EVP_PKEY_new();
    EVP_PKEY_copy_parameters(pub_key, ec_key);
    EVP_PKEY_set1_EC_KEY(pub_key, EC_KEY_dup(EVP_PKEY_get0_EC_KEY(ec_key)));
    return pub_key;
}

void printECDH(string msg, EVP_PKEY *ec_key)
{
    char *pub_key_hex = EC_POINT_point2hex(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(ec_key)), EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(ec_key)), POINT_CONVERSION_COMPRESSED, NULL);
    std::cout << msg << pub_key_hex << std::endl;
    OPENSSL_free(pub_key_hex);
}