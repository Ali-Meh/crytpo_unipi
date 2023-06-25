#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <cstring> // For memcpy
#include <cstdio>
#include <iostream>
#include "const.h"

using namespace std;

string bin2hex(unsigned char *digest, int digest_len)
{
    stringstream hashed_password_stream;
    hashed_password_stream << hex << setfill('0');
    for (int i = 0; i < digest_len; i++)
    {
        hashed_password_stream << setw(2) << static_cast<unsigned>(digest[i]);
    }
    return hashed_password_stream.str();
}

// Function to encrypt a message unsing symmetric encyption (aes cbc 256)
unsigned char *encryptAES(unsigned char *plaintext, int plainSize, int *ciphertext_len, unsigned char *privKey)
{
    int ret;

    // Encryption params
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    int ivLen = EVP_CIPHER_iv_length(cipher);
    unsigned int hmacSize = HMAC_SIZE;
    unsigned char *tag = (unsigned char *)malloc(TAG_SIZE);

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
    unsigned char *ciphertext = (unsigned char *)malloc(plainSize + EVP_CIPHER_block_size(cipher) + ivLen + hmacSize + TAG_SIZE);

    int bytesWritten = 0, encryptedSize = 0;

    // Encrypt plaintext
    ret = EVP_EncryptInit(ctx, cipher, privKey, iv);
    if (ret <= 0)
    {
        cerr << "Error during initialization for symmetric encryption\n";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ret = EVP_EncryptUpdate(ctx, ciphertext + ivLen, &bytesWritten, plaintext, plainSize);
    encryptedSize = bytesWritten;
    if (ret <= 0)
    {
        cerr << "Error during update for symmetric encryption\n";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ret = EVP_EncryptFinal(ctx, ciphertext + encryptedSize + ivLen, &bytesWritten);
    encryptedSize += bytesWritten;
    if (ret == 0)
    {
        cerr << "Error during finalization for symmetric encryption\n";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // gcm
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1)
    {
        cerr << "Error during setting controll for tag\n";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // Calculate HMAC from plaintext
    unsigned char *hmac = HMAC(EVP_sha256(), privKey, AES_KEY_SIZE, plaintext, plainSize, NULL, &hmacSize);
    if (hmac == NULL)
    {
        cerr << "Error calculating HMAC\n";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (PRINT_ENCRYPT_MESSAGES)
    {
        cout << "<< Key(Hex): " << bin2hex(privKey, AES_KEY_SIZE) << endl;
        cout << "<< Iv(Hex): " << bin2hex(iv, ivLen) << endl;
        cout << "<< Taged(Hex): " << bin2hex(tag, TAG_SIZE) << endl;
        cout << "<< HMAC(Hex): " << bin2hex(hmac, hmacSize) << endl;
    }
    // Append IV to ciphertext
    memcpy(ciphertext, iv, ivLen);
    // Append IV to ciphertext
    memcpy(ciphertext + ivLen + encryptedSize, tag, TAG_SIZE);
    // Append HMAC to ciphertext end
    memcpy(ciphertext + ivLen + encryptedSize + TAG_SIZE, hmac, hmacSize);

    // ciphertext_len = encryptedSize + ivLen + hmacSize;
    *ciphertext_len = encryptedSize + ivLen + TAG_SIZE + hmacSize;

    // clean up
    free(iv);
    free(tag);
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
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    int ivLen = EVP_CIPHER_iv_length(cipher);
    // Extract ciphertext
    cipherSize = cipherSize - ivLen - TAG_SIZE - HMAC_SIZE;
    unsigned char *plaintext = (unsigned char *)malloc(cipherSize);

    // Create context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        cerr << "Error creating context for symmetric decryption\n";
        return 0;
    }

    int bytesWritten = 0, decryptedSize = 0;

    if (PRINT_DECRYPT_MESSAGES)
    {
        cout << ">> Key(Hex): " << bin2hex(privKey, AES_KEY_SIZE) << endl;
        cout << ">> Iv(Hex): " << bin2hex(ciphertext, ivLen) << endl;
        cout << ">> Taged(Hex): " << bin2hex(ciphertext + ivLen + cipherSize, TAG_SIZE) << endl;
    }

    // Decrypt
    ret = EVP_DecryptInit(ctx, cipher, privKey, ciphertext);
    if (ret <= 0)
    {
        cerr << "Error during initialization for symmetric decryption\n";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ret = EVP_DecryptUpdate(ctx, plaintext, &bytesWritten, ciphertext + ivLen, cipherSize);
    if (ret <= 0)
    {
        cerr << "Error during update for symmetric decryption\n";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    decryptedSize = bytesWritten;

    // void *tag = iv + cipher + tag + hmac;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, ciphertext + ivLen + cipherSize) != 1)
    {
        cerr << "Error during setting controll for tag\n";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    ret = EVP_DecryptFinal_ex(ctx, plaintext + decryptedSize, &bytesWritten);
    if (ret <= 0)
    {
        cerr << "Error during finalization for symmetric decryption\n";
        EVP_CIPHER_CTX_free(ctx);
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
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (PRINT_DECRYPT_MESSAGES)
    {
        cout << ">> HMAC(Hex): " << bin2hex(calculatedHmac, hmacSize) << endl;
    }
    // Compare the calculated HMAC with the HMAC extracted from the ciphertext
    if (memcmp(calculatedHmac, ciphertext + ivLen + cipherSize + TAG_SIZE, HMAC_SIZE) != 0)
    {
        cerr << "HMAC verification failed. The ciphertext may have been tampered with.\n";
        EVP_CIPHER_CTX_free(ctx);
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
