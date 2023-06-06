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
EVP_PKEY *generateECDHEVP_PKEY()
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
EC_KEY *generateECDHEC_KEY()
{
    // Create a new EC_KEY object
    EC_KEY *key = EC_KEY_new();
    if (!key)
    {
        cerr << "Failed to create EC_KEY object" << endl;
        return nullptr;
    }

    // Generate the EC key parameters
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group)
    {
        cerr << "Failed to create EC_GROUP object" << endl;
        EC_KEY_free(key);
        return nullptr;
    }

    if (EC_KEY_set_group(key, group) != 1)
    {
        cerr << "Failed to set EC_GROUP for EC_KEY" << endl;
        EC_GROUP_free(group);
        EC_KEY_free(key);
        return nullptr;
    }

    // Generate the EC key pair
    if (EC_KEY_generate_key(key) != 1)
    {
        cerr << "Failed to generate EC key pair" << endl;
        EC_GROUP_free(group);
        EC_KEY_free(key);
        return nullptr;
    }

    EC_GROUP_free(group);

    return key;
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
    cout << msg << pub_key_hex << endl;
    OPENSSL_free(pub_key_hex);
}

void save_keypair_to_file(EC_KEY *keypair, const char *private_key_path, const char *public_key_path)
{
    BIO *private_key_bio = BIO_new_file(private_key_path, "w");
    if (private_key_bio)
    {
        PEM_write_bio_ECPrivateKey(private_key_bio, keypair, nullptr, nullptr, 0, nullptr, nullptr);
        BIO_free(private_key_bio);
    }

    BIO *public_key_bio = BIO_new_file(public_key_path, "w");
    if (public_key_bio)
    {
        PEM_write_bio_EC_PUBKEY(public_key_bio, keypair);
        BIO_free(public_key_bio);
    }
}

EC_KEY *load_private_key(string private_key_path)
{
    EC_KEY *keypair = nullptr;

    // Load the private key from file
    // Replace this implementation with your own file loading logic
    // Example:
    BIO *private_key_bio = BIO_new_file(private_key_path.c_str(), "r");
    if (private_key_bio)
    {
        keypair = PEM_read_bio_ECPrivateKey(private_key_bio, nullptr, nullptr, nullptr);
        BIO_free(private_key_bio);
    }
    return keypair;
}

string pubkey_tostring(EC_KEY *keypair)
{
    EVP_PKEY *evp_pubkey = EVP_PKEY_new();
    if (!evp_pubkey)
    {
        cerr << "Failed to create EVP_PKEY object" << endl;
        return "";
    }

    if (EVP_PKEY_set1_EC_KEY(evp_pubkey, keypair) != 1)
    {
        cerr << "Failed to set EC_KEY for EVP_PKEY" << endl;
        EVP_PKEY_free(evp_pubkey);
        return "";
    }

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        cerr << "Failed to create BIO object" << endl;
        EVP_PKEY_free(evp_pubkey);
        return "";
    }

    if (PEM_write_bio_PUBKEY(bio, evp_pubkey) != 1)
    {
        cerr << "Failed to write public key to BIO" << endl;
        BIO_free(bio);
        EVP_PKEY_free(evp_pubkey);
        return "";
    }

    char *pubkey_data = nullptr;
    long pubkey_len = BIO_get_mem_data(bio, &pubkey_data);
    string pubkey_pem(pubkey_data, pubkey_len);

    BIO_free(bio);
    EVP_PKEY_free(evp_pubkey);

    return pubkey_pem;
}