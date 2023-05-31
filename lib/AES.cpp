#include <openssl/rand.h>
#include <openssl/evp.h>
#include <cstring> // For memcpy
#include <cstdio>
#include "util.cpp"
#include "const.h"

// namespace hash
// {
// #include "hash.cpp"
// }

#define KEY_SIZE 16
// AES key size in bytes
const int AES_KEY_SIZE = 16; // 128 bits

// Encrypts input plaintext using AES-256 CBC mode with an IV prepended to the ciphertext
// key: 32-byte encryption key
// plaintext: input data to be encrypted
// plaintextLength: length of the plaintext in bytes
// ciphertextLength: pointer to store the length of the ciphertext (IV + encrypted data)
// Returns the dynamically allocated ciphertext buffer
// char *encryptAES256(const unsigned char *key, const char *plaintext, size_t plaintextLength,
//                     size_t *ciphertextLength)
// {
//     AES_KEY aesKey;
//     AES_set_encrypt_key(key, 256, &aesKey);

//     size_t encryptedDataLength = AES_BLOCK_SIZE + plaintextLength; // IV + ciphertext

//     // Generate a random IV
//     unsigned char iv[AES_BLOCK_SIZE];
//     RAND_bytes(iv, AES_BLOCK_SIZE);

//     *ciphertextLength = encryptedDataLength;

//     // Allocate memory for ciphertext (including IV)
//     char *ciphertext = new char[*ciphertextLength];

//     // Copy the IV to the beginning of the ciphertext buffer
//     memcpy(reinterpret_cast<unsigned char *>(ciphertext), iv, AES_BLOCK_SIZE);

//     AES_cbc_encrypt(reinterpret_cast<const unsigned char *>(plaintext),
//                     reinterpret_cast<unsigned char *>(ciphertext + AES_BLOCK_SIZE),
//                     plaintextLength, &aesKey, iv, AES_ENCRYPT);
//     printf("encrypting with iv:%s and key: %s\n> %s\n", bin_to_hex((unsigned char *)ciphertext, KEY_SIZE).data(), bin_to_hex((unsigned char *)key, 32).data(), bin_to_hex(reinterpret_cast<unsigned char *>(ciphertext), encryptedDataLength + 5).data());
//     return ciphertext;
// }

// Function to encrypt a message unsing symmetric encyption (aes cbc 256)
int encryptSym(unsigned char *plaintext, int plainSize, unsigned char *ciphertext, unsigned char *privKey)
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

    // Create context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        cerr << "Error creating context for symmetric encryption\n";
        return 0;
    }
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

    return encryptedSize;
}

// // Decrypts input ciphertext (with IV prepended) using AES-256 CBC mode
// // key: 32-byte decryption key
// // ciphertext: input data to be decrypted (including the IV)
// // ciphertextLength: length of the ciphertext (IV + encrypted data) in bytes
// // plaintextLength: pointer to store the length of the plaintext
// // Returns the dynamically allocated plaintext buffer
// char *decryptAES256(const unsigned char *key, const unsigned char *ciphertext, size_t ciphertextLength,
//                     size_t *plaintextLength)
// {
//     AES_KEY aesKey;
//     AES_set_decrypt_key(key, 256, &aesKey);

//     size_t decryptedDataLength = ciphertextLength - AES_BLOCK_SIZE; // Exclude IV

//     // Extract the IV from the ciphertext
//     unsigned char iv[AES_BLOCK_SIZE];
//     memcpy(iv, ciphertext, AES_BLOCK_SIZE);

//     *plaintextLength = decryptedDataLength;

//     // Allocate memory for plaintext
//     char *plaintext = new char[*plaintextLength + 1]; // +1 for null-terminator

//     AES_cbc_encrypt(ciphertext + AES_BLOCK_SIZE, reinterpret_cast<unsigned char *>(plaintext),
//                     decryptedDataLength, &aesKey, iv, AES_DECRYPT);

//     plaintext[*plaintextLength] = '\0'; // Add null-terminator at the end
//     printf("decrypting with iv:%s and key: %s\n", bin_to_hex((unsigned char *)ciphertext, KEY_SIZE).data(), bin_to_hex((unsigned char *)key, 32).data());
//     return plaintext;
// }
int decryptSym(unsigned char *ciphertext, int cipherSize, unsigned char *plaintext, unsigned char *privKey)
{

    int ret;

    // Decryption params
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();

    // Create context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        cerr << "Error creating context for symmetric decryption\n";
        return 0;
    }
    int bytesWritten;
    int decryptedSize;

    // Decrypt
    ret = EVP_DecryptInit(ctx, cipher, privKey, ciphertext);
    if (ret <= 0)
    {
        cerr << "Error during initialization for symmetric decryption\n";
        return 0;
    }
    ret = EVP_DecryptUpdate(ctx, plaintext, &bytesWritten, ciphertext + ivSize, cipherSize);
    if (ret <= 0)
    {
        cerr << "Error during update for symmetric decryption\n";
        return 0;
    }
    decryptedSize = bytesWritten;
    ret = EVP_DecryptFinal(ctx, plaintext + decryptedSize, &bytesWritten);
    if (ret <= 0)
    {
        cerr << "Error during finalization for symmetric decryption\n";
        return 0;
    }
    decryptedSize += bytesWritten;
    EVP_CIPHER_CTX_free(ctx);

    return decryptedSize;
}

// Generates a secure random key with the specified length in bytes
// keyLength: length of the key in bytes
// key: output buffer to store the generated key
void generateRandomKey(size_t keyLength, unsigned char *key)
{
    RAND_bytes(key, keyLength);
}

// Generate an AES key
// std::string generate_aes_key()
// {
//     unsigned char *aes_key = new unsigned char[AES_KEY_SIZE];
//     RAND_bytes(aes_key, AES_KEY_SIZE);
//     unsigned int digest_len = 32;
//     unsigned char digest[digest_len];

//     sha256(aes_key, AES_KEY_SIZE, digest, &digest_len);
//     std::string str(reinterpret_cast<char *>(digest), digest_len);
//     printf("Generated key: %s  -> %s \n%s\n", digest, str.data(), bin_to_hex(digest, digest_len).data());
//     return str;
// }

// Example usage
int main()
{
    const size_t keyLength = 32; // 256 bits

    // Generate random key
    unsigned char key[keyLength];
    generateRandomKey(keyLength, key);

    // Input plaintext
    const char *plaintext = "Hello, AES! This is a variable-sized input. I'm just trying to make it more.";
    size_t plaintextLength = strlen(plaintext);

    // // Calculate ciphertext length (IV + encrypted data)
    // size_t ciphertextLength;
    // unsigned char *ciphertext = encryptAES256(key, (unsigned char *)plaintext, plaintextLength, &ciphertextLength);

    // // Decrypt the ciphertext
    // size_t decryptedPlaintextLength;
    // unsigned char *decryptedPlaintext = decryptAES256(key, reinterpret_cast<unsigned char *>(ciphertext), ciphertextLength, &decryptedPlaintextLength);

    // Calculate ciphertext length (IV + encrypted data)
    unsigned char *ciphertext = (unsigned char *)malloc(plaintextLength + blockSize + ivSize);
    size_t ciphertextLength = encryptSym((unsigned char *)plaintext, plaintextLength, ciphertext, key);

    // Decrypt the ciphertext
    unsigned char *decryptedPlaintext = (unsigned char *)malloc(plaintextLength + blockSize);
    size_t decryptedPlaintextLength = decryptSym(ciphertext, ciphertextLength, decryptedPlaintext, key);

    // Print the results
    printf("Plaintext: %s\n", plaintext);
    printf("Key: %s\n", bin_to_hex(key, keyLength).data());
    printf("Ciphertext (with IV): (%s) %s\n", bin_to_hex(ciphertext, ivSize).data(), bin_to_hex(reinterpret_cast<unsigned char *>(ciphertext), ciphertextLength + ivSize).data());
    printf("Decrypted: %.*s\n", static_cast<int>(decryptedPlaintextLength), decryptedPlaintext);

    // Clean up
    delete[] ciphertext;
    delete[] decryptedPlaintext;

    return 0;
}
