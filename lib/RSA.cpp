#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string>
#include <vector>

using namespace std;

namespace rsa
{

    const char *PUB_FILE = "pub.pem";
    const char *PRV_FILE = "prv.pem";
    EVP_PKEY *load_private_key(const char *filename = PRV_FILE, char *password = nullptr)
    {
        FILE *file = fopen(filename, "rb");
        if (file == NULL)
        {
            return NULL;
        }
        EVP_PKEY *keypair = PEM_read_PrivateKey(file, nullptr, nullptr, password);
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
        RSA *keypair = PEM_read_RSAPublicKey(file, nullptr, nullptr, nullptr);
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
        BIO *bp_public = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPublicKey(bp_public, keypair);

        // Save the public key in the client's pubkey variable
        char *pubkey_buf = nullptr;
        long pubkey_len = BIO_get_mem_data(bp_public, &pubkey_buf);

        string pubkey = string(pubkey_buf, pubkey_len);

        BIO_free(bp_public);
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

    // Extracts the public key from EVP_PKEY as unsigned char*
    // Returns the public key data as an unsigned char* or nullptr on error
    unsigned char *extractPublicKey(EVP_PKEY *private_key, size_t &public_key_length)
    {
        // Create a new BIO
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio)
        {
            fprintf(stderr, "Error creating BIO\n");
            return nullptr;
        }

        // Write the public key data to the BIO
        if (!PEM_write_bio_PUBKEY(bio, private_key))
        {
            fprintf(stderr, "Error writing public key to BIO\n");
            BIO_free(bio);
            return nullptr;
        }

        // Get the length of the public key data
        long keyLength = BIO_pending(bio);
        if (keyLength <= 0)
        {
            fprintf(stderr, "Error getting public key length\n");
            BIO_free(bio);
            return nullptr;
        }

        // Allocate memory for the public key data
        unsigned char *publicKeyData = new unsigned char[keyLength];

        // Read the public key data from the BIO into the memory buffer
        if (BIO_read(bio, publicKeyData, keyLength) <= 0)
        {
            fprintf(stderr, "Error reading public key from BIO\n");
            BIO_free(bio);
            delete[] publicKeyData;
            return nullptr;
        }

        // Clean up the BIO
        BIO_free(bio);

        // Update the output parameter with the public key length
        public_key_length = static_cast<size_t>(keyLength);

        return publicKeyData;
    }

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

    unsigned char *encryptPubRSA(unsigned char *message, size_t message_len, unsigned char *publicKeyPEM, size_t key_len, size_t &cipher_length)
    {
        BIO *publicKeyBio = BIO_new_mem_buf(publicKeyPEM, key_len);
        if (!publicKeyBio)
        {
            fprintf(stderr, "Error creating BIO for public key\n");
            return nullptr;
        }

        RSA *rsaKey = PEM_read_bio_RSA_PUBKEY(publicKeyBio, nullptr, nullptr, nullptr);
        if (!rsaKey)
        {
            fprintf(stderr, "Error reading public key\n");
            BIO_free(publicKeyBio);
            return nullptr;
        }

        int rsaSize = RSA_size(rsaKey);
        unsigned char *ciphertext = new unsigned char[rsaSize];

        int encryptedSize = RSA_public_encrypt(static_cast<int>(message_len), message, ciphertext, rsaKey, RSA_PKCS1_OAEP_PADDING);
        if (encryptedSize == -1)
        {
            fprintf(stderr, "Error encrypting data: %s\n", ERR_error_string(ERR_get_error(), nullptr));
            RSA_free(rsaKey);
            BIO_free(publicKeyBio);
            delete[] ciphertext;
            return nullptr;
        }

        cipher_length = static_cast<size_t>(encryptedSize);

        RSA_free(rsaKey);
        BIO_free(publicKeyBio);

        return ciphertext;
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
    unsigned char *decryptPrvRSA(unsigned char *cipher, size_t cipher_len, EVP_PKEY *privateKey, size_t &decrypted_len)
    {
        if (!cipher || cipher_len == 0 || !privateKey)
        {
            fprintf(stderr, "Invalid input parameters\n");
            return nullptr;
        }

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
        if (!ctx)
        {
            fprintf(stderr, "Error creating EVP_PKEY_CTX\n");
            return nullptr;
        }

        if (EVP_PKEY_decrypt_init(ctx) <= 0)
        {
            fprintf(stderr, "Error initializing RSA decryption\n");
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        {
            fprintf(stderr, "Error setting RSA padding\n");
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }

        size_t outlen;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, cipher, cipher_len) <= 0)
        {
            fprintf(stderr, "Error getting decrypted output length\n");
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }

        unsigned char *decrypted = new unsigned char[outlen];
        if (!decrypted)
        {
            fprintf(stderr, "Error allocating memory for decrypted data\n");
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }

        if (EVP_PKEY_decrypt(ctx, decrypted, &outlen, cipher, cipher_len) <= 0)
        {
            fprintf(stderr, "Error decrypting RSA data\n");
            delete[] decrypted;
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }

        EVP_PKEY_CTX_free(ctx);
        decrypted_len = outlen;
        return decrypted;
    }
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

    unsigned char *calculateSharedSecret(DH *dhParams, const unsigned char *publicKey, size_t publicKeyLen, size_t &sharedSecretLen)
    {
        if (!dhParams || !publicKey || publicKeyLen == 0)
        {
            fprintf(stderr, "Invalid input parameters\n");
            return nullptr;
        }

        DH_set0_key(dhParams, nullptr, BN_bin2bn(publicKey, static_cast<int>(publicKeyLen), nullptr));

        if (DH_generate_key(dhParams) != 1)
        {
            fprintf(stderr, "Error generating DH key pair\n");
            return nullptr;
        }

        const BIGNUM *pubKey = nullptr;
        DH_get0_key(dhParams, &pubKey, nullptr);

        size_t secretLen = DH_size(dhParams);
        unsigned char *sharedSecret = new unsigned char[secretLen];
        if (!sharedSecret)
        {
            fprintf(stderr, "Error allocating memory for shared secret\n");
            return nullptr;
        }

        int sharedSecretLenCalc = DH_compute_key(sharedSecret, pubKey, dhParams);
        if (sharedSecretLenCalc < 0)
        {
            fprintf(stderr, "Error computing shared secret\n");
            delete[] sharedSecret;
            return nullptr;
        }

        sharedSecretLen = static_cast<size_t>(sharedSecretLenCalc);
        return sharedSecret;
    }
}