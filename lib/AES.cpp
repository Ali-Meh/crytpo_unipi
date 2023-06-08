#include <openssl/rand.h>
#include <openssl/evp.h>
#include <cstring> // For memcpy
#include <cstdio>
#include <iostream>
// #include "const.h"

using namespace std;

// Function to encrypt a message unsing symmetric encyption (aes cbc 256)
unsigned char *encryptAES(unsigned char *plaintext, int plainSize, int *ciphertext_len, unsigned char *privKey)
{

    int ret;
    unsigned char *iv = (unsigned char *)malloc(ivSize);
    // Encryption params
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    int ivLen = EVP_CIPHER_iv_length(cipher);

    // Create iv
    RAND_poll();
    ret = RAND_bytes(iv, ivLen);
    if (!ret)
    {
        cerr << "Error randomizing iv for symmetric encrytpion\n";
        return 0;
    }
    // printf("Encrypting with IV: %s Key: %s\n", bin_to_hex(iv, ivSize).data(), bin_to_hex(privKey, AES_KEY_SIZE).data());

    // Create context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        cerr << "Error creating context for symmetric encryption\n";
        return 0;
    }
    unsigned char *ciphertext = (unsigned char *)malloc(plainSize + EVP_CIPHER_block_size(cipher) + ivLen);

    int bytesWritten;
    int encryptedSize;

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
    EVP_CIPHER_CTX_free(ctx);
    mempcpy(ciphertext, iv, ivLen);

    // ciphertext_len encryptedSize + ivLen;
    *ciphertext_len = encryptedSize + ivLen;
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
    unsigned char *plaintext = (unsigned char *)malloc(2 * (cipherSize - ivLen));

    // Create context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        cerr << "Error creating context for symmetric decryption\n";
        return 0;
    }
    int bytesWritten;
    int decryptedSize;

    // printf("Decrypting with IV: %s Key: %s\n", bin_to_hex(ciphertext, ivLen).data(), bin_to_hex(privKey, AES_KEY_SIZE).data());

    // Decrypt
    ret = EVP_DecryptInit(ctx, cipher, privKey, ciphertext);
    if (ret <= 0)
    {
        cerr << "Error during initialization for symmetric decryption\n";
        return 0;
    }
    ret = EVP_DecryptUpdate(ctx, plaintext, &bytesWritten, ciphertext + ivSize, cipherSize - ivLen);
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
    EVP_CIPHER_CTX_free(ctx);
    *plaintext_size = decryptedSize;
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
    unsigned int digest_len = 32;
    unsigned char digest[digest_len];

    EVP_Digest(aes_key, AES_KEY_SIZE, digest, &digest_len, EVP_sha256(), NULL);
    std::string str(reinterpret_cast<char *>(digest), digest_len);
    // printf("Generated key: %s  -> %s \n%s\n", digest, str.data(), bin_to_hex(digest, digest_len).data());
    return str;
}

// // Example usage
// int main()
// {
//     const size_t keyLength = 32; // 256 bits

//     // Generate random key
//     unsigned char key[keyLength];
//     generateRandomKey(keyLength, key);

//     // Input plaintext
//     const char *plaintext = "Hello, AES! This is a variable-sized input. I'm just trying to make it more.";
//     size_t plaintextLength = strlen(plaintext);

//     // // Calculate ciphertext length (IV + encrypted data)
//     // size_t ciphertextLength;
//     // unsigned char *ciphertext = encryptAES256(key, (unsigned char *)plaintext, plaintextLength, &ciphertextLength);

//     // // Decrypt the ciphertext
//     // size_t decryptedPlaintextLength;
//     // unsigned char *decryptedPlaintext = decryptAES256(key, reinterpret_cast<unsigned char *>(ciphertext), ciphertextLength, &decryptedPlaintextLength);

//     // Calculate ciphertext length (IV + encrypted data)
//     unsigned char *ciphertext = (unsigned char *)malloc(plaintextLength + blockSize + ivSize);
//     size_t ciphertextLength = encryptAES((unsigned char *)plaintext, plaintextLength, ciphertext, key);

//     // Decrypt the ciphertext
//     unsigned char *decryptedPlaintext = (unsigned char *)malloc(plaintextLength + blockSize);
//     size_t decryptedPlaintextLength = decryptAES(ciphertext, ciphertextLength, decryptedPlaintext, key);

//     // Print the results
//     printf("Plaintext: %s\n", plaintext);
//     printf("Key: %s\n", bin_to_hex(key, keyLength).data());
//     printf("Ciphertext (with IV): (%s) %s\n", bin_to_hex(ciphertext, ivSize).data(), bin_to_hex(reinterpret_cast<unsigned char *>(ciphertext), ciphertextLength + ivSize).data());
//     printf("Decrypted: %.*s\n", static_cast<int>(decryptedPlaintextLength), decryptedPlaintext);

//     // Clean up
//     delete[] ciphertext;
//     delete[] decryptedPlaintext;

//     return 0;
// }
