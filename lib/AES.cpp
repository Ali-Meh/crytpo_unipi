#include <openssl/aes.h>
#include <openssl/rand.h>
#include <cstring> // For memcpy
#include <cstdio>
#include "util.cpp"

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
char *encryptAES256(const unsigned char *key, const char *plaintext, size_t plaintextLength,
                    size_t *ciphertextLength)
{
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 256, &aesKey);

    size_t encryptedDataLength = AES_BLOCK_SIZE + plaintextLength; // IV + ciphertext

    // Generate a random IV
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    *ciphertextLength = encryptedDataLength;

    // Allocate memory for ciphertext (including IV)
    char *ciphertext = new char[*ciphertextLength];

    // Copy the IV to the beginning of the ciphertext buffer
    memcpy(reinterpret_cast<unsigned char *>(ciphertext), iv, AES_BLOCK_SIZE);

    AES_cbc_encrypt(reinterpret_cast<const unsigned char *>(plaintext),
                    reinterpret_cast<unsigned char *>(ciphertext + AES_BLOCK_SIZE),
                    plaintextLength, &aesKey, iv, AES_ENCRYPT);

    return ciphertext;
}

// Decrypts input ciphertext (with IV prepended) using AES-256 CBC mode
// key: 32-byte decryption key
// ciphertext: input data to be decrypted (including the IV)
// ciphertextLength: length of the ciphertext (IV + encrypted data) in bytes
// plaintextLength: pointer to store the length of the plaintext
// Returns the dynamically allocated plaintext buffer
char *decryptAES256(const unsigned char *key, const unsigned char *ciphertext, size_t ciphertextLength,
                    size_t *plaintextLength)
{
    AES_KEY aesKey;
    AES_set_decrypt_key(key, 256, &aesKey);

    size_t decryptedDataLength = ciphertextLength - AES_BLOCK_SIZE; // Exclude IV

    // Extract the IV from the ciphertext
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, ciphertext, AES_BLOCK_SIZE);

    *plaintextLength = decryptedDataLength;

    // Allocate memory for plaintext
    char *plaintext = new char[*plaintextLength + 1]; // +1 for null-terminator

    AES_cbc_encrypt(ciphertext + AES_BLOCK_SIZE, reinterpret_cast<unsigned char *>(plaintext),
                    decryptedDataLength, &aesKey, iv, AES_DECRYPT);

    plaintext[*plaintextLength] = '\0'; // Add null-terminator at the end

    return plaintext;
}

// Generates a secure random key with the specified length in bytes
// keyLength: length of the key in bytes
// key: output buffer to store the generated key
void generateRandomKey(size_t keyLength, unsigned char *key)
{
    RAND_bytes(key, keyLength);
}

// // Generate an AES key
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
    const char *plaintext = "Hello, AES! This is a variable-sized input.";
    size_t plaintextLength = strlen(plaintext);

    // Calculate ciphertext length (IV + encrypted data)
    size_t ciphertextLength;
    char *ciphertext = encryptAES256(key, (char *)plaintext,
                                     plaintextLength, &ciphertextLength);

    // Decrypt the ciphertext
    size_t decryptedPlaintextLength;
    char *decryptedPlaintext = decryptAES256(key, reinterpret_cast<unsigned char *>(ciphertext), ciphertextLength, &decryptedPlaintextLength);

    // Print the results
    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext (with IV): ");
    // for (size_t i = 0; i < ciphertextLength; ++i)
    // {
    //     printf("%02x", ciphertext[i]);
    // }
    // printf("%.*s\n", ciphertext);

    printf("Decrypted Text: %.*s\n", static_cast<int>(decryptedPlaintextLength), decryptedPlaintext);

    // Clean up
    delete[] ciphertext;
    delete[] decryptedPlaintext;

    return 0;
}
