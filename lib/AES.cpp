#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>

namespace hash
{
#include "hash.cpp"
}

#define KEY_SIZE 16
// AES key size in bytes
const int AES_KEY_SIZE = 16; // 128 bits

// Encrypt the data using AES
char *encrypt_data(char *input_data, int input_size, char *aes_key)
{
    unsigned char *aes_iv = new unsigned char[KEY_SIZE];
    unsigned char *output_data = new unsigned char[input_size];
    memset(aes_iv, 0, KEY_SIZE);
    memset(output_data, 0, input_size);
    memcpy(aes_iv, aes_key, KEY_SIZE);
    AES_KEY aes;
    AES_set_encrypt_key((unsigned char *)aes_key, KEY_SIZE * 8, &aes);
    AES_cbc_encrypt((unsigned char *)input_data, output_data, input_size, &aes, aes_iv, AES_ENCRYPT);
    printf("encrypting with iv:%s and key: %s\n", bin_to_hex(aes_iv, KEY_SIZE), bin_to_hex((unsigned char *)aes_key, strlen(aes_key)));
    delete[] aes_iv;
    return (char *)output_data;
}

// Decrypt the data using AES
char *decrypt_data(char *input_data, int input_size, char *aes_key)
{
    unsigned char *aes_iv = new unsigned char[KEY_SIZE];
    unsigned char *output_data = new unsigned char[input_size];
    memset(aes_iv, 0, KEY_SIZE);
    memset(output_data, 0, input_size);
    memcpy(aes_iv, aes_key, KEY_SIZE);
    AES_KEY aes;
    AES_set_decrypt_key((unsigned char *)aes_key, KEY_SIZE * 8, &aes);
    AES_cbc_encrypt((unsigned char *)input_data, output_data, input_size, &aes, aes_iv, AES_DECRYPT);
    printf("decrypting with iv:%s and key: %s\n", bin_to_hex(aes_iv, KEY_SIZE), bin_to_hex((unsigned char *)aes_key, KEY_SIZE));
    delete[] aes_iv;
    return (char *)output_data;
}

// Generate an AES key
std::string generate_aes_key()
{
    unsigned char *aes_key = new unsigned char[AES_KEY_SIZE];
    RAND_bytes(aes_key, AES_KEY_SIZE);
    unsigned int digest_len = 32;
    unsigned char digest[digest_len];

    sha256(aes_key, AES_KEY_SIZE, digest, &digest_len);
    std::string str(reinterpret_cast<char *>(digest), digest_len);
    printf("Generated key: %s  -> %s \n%s\n", digest, str.data(), bin_to_hex(digest, digest_len).data());
    return str;
}
