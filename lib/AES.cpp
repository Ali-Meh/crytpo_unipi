#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <cstring> // For memcpy
#include <cstdio>
#include <iostream>
#include "const.h"

using namespace std;

// Function to encrypt a message unsing symmetric encyption (aes cbc 256)
unsigned char *encryptAES(unsigned char *plaintext, int plainSize, int *ciphertext_len, unsigned char *privKey)
{
    int ret;

    // Encryption params
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    int ivLen = EVP_CIPHER_iv_length(cipher);
    unsigned int hmacSize = HMAC_SIZE;

    // Create IV
    unsigned char *iv = (unsigned char *)malloc(ivLen);
    RAND_poll();
    ret = RAND_bytes(iv, ivLen);
    if (!ret)
    {
        cerr << "Error randomizing iv for symmetric encryption\n";
        return 0;
    }

    // Create context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        cerr << "Error creating context for symmetric encryption\n";
        return 0;
    }

    // Allocate memory for ciphertext
    unsigned char *ciphertext = (unsigned char *)malloc(plainSize + EVP_CIPHER_block_size(cipher) + ivLen + hmacSize);

    int bytesWritten = 0, encryptedSize = 0;

    // Encrypt plaintext
    ret = EVP_EncryptInit(ctx, cipher, privKey, iv);
    if (ret <= 0)
    {
        cerr << "Error during initialization for symmetric encryption\n";
        return 0;
    }
    ret = EVP_EncryptUpdate(ctx, ciphertext + ivLen, &bytesWritten, plaintext, plainSize);
    encryptedSize = bytesWritten;
    if (ret <= 0)
    {
        cerr << "Error during update for symmetric encryption\n";
        return 0;
    }
    ret = EVP_EncryptFinal(ctx, ciphertext + encryptedSize + ivLen, &bytesWritten);
    encryptedSize += bytesWritten;
    if (ret == 0)
    {
        cerr << "Error during finalization for symmetric encryption\n";
        return 0;
    }

    // Calculate HMAC from plaintext
    unsigned char *hmac = HMAC(EVP_sha256(), privKey, AES_KEY_SIZE, plaintext, plainSize, NULL, &hmacSize);
    if (hmac == NULL)
    {
        cerr << "Error calculating HMAC\n";
        return 0;
    }

    // Append IV to ciphertext
    memcpy(ciphertext, iv, ivLen);
    // Append HMAC to ciphertext end
    memcpy(ciphertext + ivLen + encryptedSize, hmac, hmacSize);

    // ciphertext_len = encryptedSize + ivLen + hmacSize;
    *ciphertext_len = encryptedSize + ivLen + hmacSize;

    // clean up
    free(iv);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// Decrypts input ciphertext (with IV prepended) using AES-256 CBC mode
// key: 32-byte decryption key
// ciphertext: input data to be decrypted (including the IV)
// ciphertextLength: length of the ciphertext (IV + encrypted data) in bytes
// plaintextLength: pointer to store the length of the plaintext
// Returns the dynamically allocated plaintext buffer
unsigned char *decryptAES(unsigned char *ciphertext, int cipherSize, unsigned int *plaintext_size, unsigned char *privKey)
{

    int ret;

    // Decryption params
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    int ivLen = EVP_CIPHER_iv_length(cipher);
    unsigned char *plaintext = (unsigned char *)malloc(cipherSize - ivLen - HMAC_SIZE);

    // Create context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        cerr << "Error creating context for symmetric decryption\n";
        return 0;
    }

    int bytesWritten = 0, decryptedSize = 0;

    // Extract IV
    cipherSize = cipherSize - ivLen - HMAC_SIZE;

    // Decrypt
    ret = EVP_DecryptInit(ctx, cipher, privKey, ciphertext);
    if (ret <= 0)
    {
        cerr << "Error during initialization for symmetric decryption\n";
        return 0;
    }
    ret = EVP_DecryptUpdate(ctx, plaintext, &bytesWritten, ciphertext + ivLen, cipherSize);
    if (ret <= 0)
    {
        cerr << "Error during update for symmetric decryption\n";
        return 0;
    }
    decryptedSize = bytesWritten;
    ret = EVP_DecryptFinal_ex(ctx, plaintext + decryptedSize, &bytesWritten);
    if (ret <= 0)
    {
        cerr << "Error during finalization for symmetric decryption\n";
        return 0;
    }
    decryptedSize += bytesWritten;
    *plaintext_size = decryptedSize;

    // Calculate HMAC from the decrypted plaintext
    unsigned int hmacSize;
    unsigned char *calculatedHmac = HMAC(EVP_sha256(), privKey, AES_KEY_SIZE, plaintext, decryptedSize, NULL, &hmacSize);
    if (calculatedHmac == NULL)
    {
        cerr << "Error calculating HMAC\n";
        return 0;
    }
    // Compare the calculated HMAC with the HMAC extracted from the ciphertext
    if (memcmp(calculatedHmac, ciphertext + ivLen + cipherSize, HMAC_SIZE) != 0)
    {
        cerr << "HMAC verification failed. The ciphertext may have been tampered with.\n";
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// Generates a secure random key with the specified length in bytes
// keyLength: length of the key in bytes
// key: output buffer to store the generated key
void generateRandomKey(size_t keyLength, unsigned char *key)
{
    RAND_bytes(key, keyLength);
}

// Generate an AES key
std::string generate_aes_key()
{
    unsigned char *aes_key = new unsigned char[AES_KEY_SIZE];
    RAND_bytes(aes_key, AES_KEY_SIZE);
    unsigned int digest_len = AES_KEY_SIZE;
    unsigned char digest[digest_len];

    EVP_Digest(aes_key, AES_KEY_SIZE, digest, &digest_len, EVP_sha256(), NULL);
    std::string str(reinterpret_cast<char *>(digest), digest_len);
    // printf("Generated key: %s  -> %s \n%s\n", digest, str.data(), bin_to_hex(digest, digest_len).data());
    return str;
}
