#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>

namespace hash
{
#include "hash.cpp"
}

#define PORT 8080
#define KEY_SIZE 16
// AES key size in bytes
const int AES_KEY_SIZE = 16; // 128 bits

// Encrypt the data using AES
unsigned char *encrypt_data(unsigned char *input_data, int input_size, unsigned char *aes_key)
{
    unsigned char *aes_iv = new unsigned char[KEY_SIZE];
    unsigned char *output_data = new unsigned char[input_size];
    memset(aes_iv, 0, KEY_SIZE);
    memset(output_data, 0, input_size);
    memcpy(aes_iv, aes_key, KEY_SIZE);
    AES_KEY aes;
    AES_set_encrypt_key(aes_key, KEY_SIZE * 8, &aes);
    AES_cbc_encrypt(input_data, output_data, input_size, &aes, aes_iv, AES_ENCRYPT);
    delete[] aes_iv;
    return output_data;
}

// Decrypt the data using AES
unsigned char *decrypt_data(unsigned char *input_data, int input_size, unsigned char *aes_key)
{
    unsigned char *aes_iv = new unsigned char[KEY_SIZE];
    unsigned char *output_data = new unsigned char[input_size];
    memset(aes_iv, 0, KEY_SIZE);
    memset(output_data, 0, input_size);
    memcpy(aes_iv, aes_key, KEY_SIZE);
    AES_KEY aes;
    AES_set_decrypt_key(aes_key, KEY_SIZE * 8, &aes);
    AES_cbc_encrypt(input_data, output_data, input_size, &aes, aes_iv, AES_DECRYPT);
    delete[] aes_iv;
    return output_data;
}

// Generate an AES key
std::string generate_aes_key()
{
    unsigned char *aes_key = new unsigned char[AES_KEY_SIZE];
    RAND_bytes(aes_key, AES_KEY_SIZE);
    unsigned char digest[64];
    unsigned int digest_len;

    sha256(aes_key, AES_KEY_SIZE, digest, &digest_len);

    std::string str(reinterpret_cast<char *>(digest), digest_len);
    return str;
}
