#include <iostream>
#include <string>
#include <stdio.h>  // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include "const.h"

const char *PUB_FILE = "keys/server_pub.pem";
const char *PRV_FILE = "keys/server_sec.pem";

using namespace std;

// Function to handle OpenSSL errors
void handleOpenSSLErrors()
{
    unsigned long error;
    while ((error = ERR_get_error()) != 0)
    {
        char *errStr = ERR_error_string(error, nullptr);
        if (errStr)
        {
            std::cerr << "OpenSSL error: " << errStr << std::endl;
        }
    }
}

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
EVP_PKEY *convertToEVP(EC_KEY *private_key)
{
    EVP_PKEY *evp_key = EVP_PKEY_new();
    if (!evp_key)
    {
        fprintf(stderr, "Error creating EVP_PKEY\n");
        return nullptr;
    }
    if (!EVP_PKEY_set1_EC_KEY(evp_key, private_key))
    {
        fprintf(stderr, "Error setting EVP_PKEY to EC_KEY\n");
        EVP_PKEY_free(evp_key);
        return nullptr;
    }
    return evp_key;
}
EVP_PKEY *convertToEVP(unsigned char *pub_key, unsigned int pub_len)
{
    // Create a BIO object to read the public key data
    BIO *bio = BIO_new_mem_buf(pub_key, pub_len);

    if (bio == nullptr)
    {
        // Handle error, e.g., memory allocation failure
        return nullptr;
    }

    // Load the PEM-formatted public key from the BIO object
    EC_KEY *loaded_key = PEM_read_bio_EC_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (loaded_key == nullptr)
    {
        // Handle error, e.g., invalid PEM data or unsupported key format
        BIO_free(bio);
        return nullptr;
    }
    // Clean up the BIO object
    BIO_free(bio);
    // // Return the loaded EVP_PKEY object
    // EVP_PKEY *evp_key = EVP_PKEY_new();
    // if (!evp_key)
    // {
    //     fprintf(stderr, "Error creating EVP_PKEY\n");
    //     return nullptr;
    // }
    // if (!EVP_PKEY_set1_EC_KEY(evp_key, loaded_key))
    // {
    //     fprintf(stderr, "Error setting EVP_PKEY to EC_KEY\n");
    //     EVP_PKEY_free(evp_key);
    //     return nullptr;
    // }
    EVP_PKEY *key = convertToEVP(loaded_key);
    EC_KEY_free(loaded_key);
    return key;
}

EVP_PKEY *load_private_key(string private_key_path)
{
    EC_KEY *keypair = nullptr;

    // Load the private key from file
    BIO *private_key_bio = BIO_new_file(private_key_path.c_str(), "r");
    if (private_key_bio)
    {
        keypair = PEM_read_bio_ECPrivateKey(private_key_bio, nullptr, nullptr, nullptr);
        BIO_free(private_key_bio);
    }
    EVP_PKEY *key = convertToEVP(keypair);
    EC_KEY_free(keypair);
    return key;
}

EC_KEY *load_public_key(const char *filename = PUB_FILE)
{
    FILE *file = fopen(filename, "rb");
    if (file == nullptr)
    {
        printf("WARN|load_public_key: couldn't load file: %s\n", filename);
        return nullptr;
    }

    EC_KEY *keypair = PEM_read_EC_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);

    return keypair;
}

unsigned char *extractPrivateKey(EC_KEY *private_key, size_t &private_key_length)
{
    unsigned char *key_data = nullptr;
    BIO *bio = nullptr;

    // Create a memory BIO object to write the private key data
    bio = BIO_new(BIO_s_mem());

    if (bio == nullptr)
    {
        // Handle error, e.g., memory allocation failure
        return nullptr;
    }

    // Write the private key data to the BIO object
    if (!PEM_write_bio_ECPrivateKey(bio, private_key, nullptr, nullptr, 0, nullptr, nullptr))
    {
        // Handle error, e.g., failed to write the private key data
        BIO_free(bio);
        return nullptr;
    }

    // Determine the length of the private key data
    private_key_length = BIO_pending(bio);

    // Allocate memory for the private key data
    key_data = new unsigned char[private_key_length];

    // Read the private key data from the BIO object into the memory
    if (BIO_read(bio, key_data, private_key_length) <= 0)
    {
        // Handle error, e.g., failed to read the private key data
        BIO_free(bio);
        delete[] key_data;
        return nullptr;
    }

    // Clean up the BIO object
    BIO_free(bio);

    // Return the extracted private key data
    return key_data;
}

unsigned char *extractPublicKey(EC_KEY *private_key, size_t &public_key_length)
{
    // Create a new BIO
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        fprintf(stderr, "Error creating BIO\n");
        return nullptr;
    }

    // Create an EVP_PKEY structure from the EC private key
    EVP_PKEY *evp_key = EVP_PKEY_new();
    if (!evp_key)
    {
        fprintf(stderr, "Error creating EVP_PKEY\n");
        BIO_free(bio);
        return nullptr;
    }
    if (!EVP_PKEY_set1_EC_KEY(evp_key, private_key))
    {
        fprintf(stderr, "Error setting EVP_PKEY to EC_KEY\n");
        EVP_PKEY_free(evp_key);
        BIO_free(bio);
        return nullptr;
    }

    // Write the public key data to the BIO
    if (!PEM_write_bio_PUBKEY(bio, evp_key))
    {
        fprintf(stderr, "Error writing public key to BIO\n");
        EVP_PKEY_free(evp_key);
        BIO_free(bio);
        return nullptr;
    }

    // Get the length of the public key data
    long keyLength = BIO_pending(bio);
    if (keyLength <= 0)
    {
        fprintf(stderr, "Error getting public key length\n");
        EVP_PKEY_free(evp_key);
        BIO_free(bio);
        return nullptr;
    }

    // Allocate memory for the public key data
    unsigned char *publicKeyData = new unsigned char[keyLength];

    // Read the public key data from the BIO into the memory buffer
    if (BIO_read(bio, publicKeyData, keyLength) <= 0)
    {
        fprintf(stderr, "Error reading public key from BIO\n");
        EVP_PKEY_free(evp_key);
        BIO_free(bio);
        delete[] publicKeyData;
        return nullptr;
    }

    // Clean up the EVP_PKEY and BIO
    EVP_PKEY_free(evp_key);
    BIO_free(bio);

    // Update the output parameter with the public key length
    public_key_length = static_cast<size_t>(keyLength);

    return publicKeyData;
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

// Function to verify the server's certificate with the root CA certificate and CRL
bool verifyCertificate(X509 *certificate, string ca_cert_path = ROOT_CA_CERT_PATH, string ca_crl_path = ROOT_CA_CRL_PATH)
{
    EVP_PKEY *publicKey = X509_get_pubkey(certificate);
    if (publicKey == nullptr)
    {
        std::cerr << "Failed to extract public key from the certificate." << std::endl;
        return false;
    }

    X509_STORE *store = X509_STORE_new();
    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (!lookup)
    {
        std::cerr << "Failed to create X509 lookup." << std::endl;
        return false;
    }

    // Load the root CA certificate
    if (X509_LOOKUP_load_file(lookup, ca_cert_path.c_str(), X509_FILETYPE_PEM) != 1)
    {
        std::cerr << "Failed to load root CA certificate." << std::endl;
        return false;
    }

    // Load the CRL file
    if (X509_STORE_load_locations(store, ca_crl_path.c_str(), nullptr) != 1)
    {
        std::cerr << "Failed to load CRL file." << std::endl;
        return false;
    }

    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);

    X509_STORE_CTX *storeCtx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(storeCtx, store, certificate, nullptr);

    int verifyResult = X509_verify_cert(storeCtx);
    X509_STORE_CTX_free(storeCtx);
    X509_STORE_free(store);

    EVP_PKEY_free(publicKey);

    if (verifyResult != 1)
    {
        std::cerr << "Failed to verify the server's certificate." << std::endl;
        return false;
    }

    return true;
}
// Function to read the server certificate from file
X509 *loadServerCertificate(string certificate_path = SERVER_CERT_PATH)
{
    FILE *file = fopen(certificate_path.c_str(), "r");
    if (!file)
    {
        std::cerr << "Failed to open the server certificate file." << std::endl;
        return nullptr;
    }

    X509 *certificate = PEM_read_X509(file, nullptr, nullptr, nullptr);
    if (!certificate)
    {
        std::cerr << "Failed to read the server certificate." << std::endl;
        fclose(file);
        return nullptr;
    }

    fclose(file);
    return certificate;
}

// Function to send the server certificate over a socket
std::string x509ToPEM(X509 *certificate)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_X509(bio, certificate))
    {
        BIO_free(bio);
        throw std::runtime_error("Failed to convert X509 certificate to PEM-encoded string.");
    }

    char *buffer = nullptr;
    long length = BIO_get_mem_data(bio, &buffer);
    std::string pemString(buffer, length);

    BIO_free(bio);
    return pemString;
}
X509 *pemToX509(const std::string &pemString)
{
    BIO *bio = BIO_new_mem_buf(pemString.c_str(), -1);
    if (!bio)
    {
        throw std::runtime_error("Failed to create BIO for PEM-encoded string.");
    }

    X509 *certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!certificate)
    {
        BIO_free(bio);
        throw std::runtime_error("Failed to convert PEM-encoded string to X509 certificate.");
    }

    BIO_free(bio);
    return certificate;
}