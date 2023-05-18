#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string>
#include <vector>

using namespace std;

const char *PUB_FILE = "pub.pem";
const char *PRV_FILE = "prv.pem";

RSA *load_private_key(const char *filename = PRV_FILE)
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        printf("load_private_key: couldn't load file: %s\n", filename);
        return NULL;
    }
    RSA *keypair = PEM_read_RSAPrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    return keypair;
}

RSA *load_public_key(const char *filename = PUB_FILE)
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        printf("WARN|load_public_key: couldn't load file: %s\n", filename);
        return NULL;
    }
    RSA *keypair = PEM_read_RSA_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);
    return keypair;
}

RSA *generate_keypair(int key_length = 2048)
{
    unsigned long e = RSA_F4;
    BIGNUM *bne = BN_new();
    BN_set_word(bne, e);
    RSA *keypair = RSA_new();

    if (!RSA_generate_key_ex(keypair, key_length, bne, NULL))
    {
        RSA_free(keypair);
        BN_free(bne);
        return NULL;
    }
    BN_free(bne);
    return keypair;
}

string pubkey_tostring(RSA *keypair)
{

    // Get the public key from the RSA keypair
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, keypair);
    BIO *bp_public = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bp_public, pkey);

    // Save the public key in the client's pubkey variable
    char *pubkey_buf = nullptr;
    long pubkey_len = BIO_get_mem_data(bp_public, &pubkey_buf);

    string pubkey = string(pubkey_buf, pubkey_len);

    BIO_free(bp_public);
    EVP_PKEY_free(pkey);

    return pubkey;
}

int save_keypair_to_file(RSA *keypair, const char *prv_key_file = PRV_FILE, const char *pub_key_file = PUB_FILE)
{
    BIO *bp_public = NULL, *bp_private = NULL;
    // 1. save public key
    bp_public = BIO_new_file(pub_key_file, "w+");
    int ret = PEM_write_bio_RSAPublicKey(bp_public, keypair);
    if (ret != 1)
    {
        perror("save_keypair_to_file: couldn't save public key.");
        goto free_all;
    }

    // 1. save private key
    bp_private = BIO_new_file(prv_key_file, "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, keypair, NULL, NULL, 0, NULL, NULL);
    if (ret != 1)
    {
        perror("save_keypair_to_file: couldn't save private key.");
    }

free_all:

    BIO_free_all(bp_public);
    BIO_free_all(bp_private);

    return ret;
}

// void write_to_file(const char *filename, const char *data)
// {
//     FILE *file = fopen(filename, "wb");
//     fwrite(data, strlen(data), 1, file);
//     fclose(file);
// }

// Function to encrypt a message using RSA public key

string encryptPubRSA(const string &message, const string &publicKeyPEM)
{
    // const unsigned char *publicKeyData = reinterpret_cast<const unsigned char *>(publicKeyPEM.c_str());
    BIO *bio = BIO_new_mem_buf(publicKeyPEM.c_str(), publicKeyPEM.size()); // -1 means null-terminated string
    if (!bio)
    {
        perror("Failed to create BIO");
        return "";
    }

    RSA *rsa = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!rsa)
    {
        ERR_print_errors_fp(stderr);
        return "";
    }

    int encryptedSize = RSA_size(rsa);
    vector<unsigned char> encrypted(encryptedSize);

    int result = RSA_public_encrypt(message.size(), reinterpret_cast<const unsigned char *>(message.c_str()),
                                    encrypted.data(), rsa, RSA_PKCS1_PADDING);
    if (result == -1)
    {
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        return "";
    }

    RSA_free(rsa);

    return string(reinterpret_cast<const char *>(encrypted.data()), result);
}
string encryptPubRSAFile(const string &message, const string &publicKeyPath)
{
    FILE *publicKeyFile = fopen(publicKeyPath.c_str(), "rb");
    if (!publicKeyFile)
    {
        perror("Failed to open public key file");
        return "";
    }

    RSA *rsa = PEM_read_RSAPublicKey(publicKeyFile, nullptr, nullptr, nullptr);
    fclose(publicKeyFile);

    if (!rsa)
    {
        ERR_print_errors_fp(stderr);
        return "";
    }

    int encryptedSize = RSA_size(rsa);
    vector<unsigned char> encrypted(encryptedSize);

    int result = RSA_public_encrypt(message.size(), reinterpret_cast<const unsigned char *>(message.c_str()),
                                    encrypted.data(), rsa, RSA_PKCS1_PADDING);
    if (result == -1)
    {
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        return "";
    }

    RSA_free(rsa);

    return string(reinterpret_cast<const char *>(encrypted.data()), result);
}

// Function to decrypt a message using RSA private key
string decryptPrvRSA(const string &encryptedMessage, const string &privateKeyPath)
{
    FILE *privateKeyFile = fopen(privateKeyPath.c_str(), "rb");
    if (!privateKeyFile)
    {
        perror("Failed to open private key file");
        return "";
    }

    RSA *rsa = PEM_read_RSAPrivateKey(privateKeyFile, nullptr, nullptr, nullptr);
    fclose(privateKeyFile);

    if (!rsa)
    {
        ERR_print_errors_fp(stderr);
        return "";
    }

    int decryptedSize = RSA_size(rsa);
    vector<unsigned char> decrypted(decryptedSize);

    int result = RSA_private_decrypt(encryptedMessage.size(), reinterpret_cast<const unsigned char *>(encryptedMessage.c_str()),
                                     decrypted.data(), rsa, RSA_PKCS1_PADDING);
    if (result == -1)
    {
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        return "";
    }

    RSA_free(rsa);

    return string(reinterpret_cast<const char *>(decrypted.data()), result);
}
