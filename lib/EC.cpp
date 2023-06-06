#include <iostream>
#include <string>
#include <stdio.h>  // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

using namespace std;

EVP_PKEY *get_dh2048_auto(void)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (pctx == nullptr)
    {
        std::cerr << "Failed to create EVP_PKEY_CTX\n";
        return nullptr;
    }

    if (EVP_PKEY_paramgen_init(pctx) <= 0)
    {
        std::cerr << "Failed to initialize paramgen: " << ERR_error_string(ERR_get_error(), nullptr) << '\n';
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, 2048) <= 0)
    {
        std::cerr << "Failed to set prime length: " << ERR_error_string(ERR_get_error(), nullptr) << '\n';
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_dh_paramgen_generator(pctx, DH_GENERATOR_2) <= 0)
    {
        std::cerr << "Failed to set generator: " << ERR_error_string(ERR_get_error(), nullptr) << '\n';
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }

    EVP_PKEY *params = nullptr;
    if (EVP_PKEY_paramgen(pctx, &params) <= 0)
    {
        std::cerr << "Failed to generate parameters: " << ERR_error_string(ERR_get_error(), nullptr) << '\n';
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }

    FILE *params_file = fopen("params.pem", "w");

    EVP_PKEY_CTX_free(pctx);
    return params;
}

int handleErrors()
{
    std::cerr << "Error: " << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    exit(1);
}

int main()
{
    /*GENERATING MY EPHEMERAL KEY*/
    /* Use built-in parameters */
    printf("Start: loading standard DH parameters\n");

    // check if params exist
    EVP_PKEY *params;
    if (NULL == (params = EVP_PKEY_new()))
        handleErrors();
    DH *temp;

    FILE *params_file = fopen("params.pem", "wr");
    if (params_file == nullptr)
    {
        std::cerr << "Failed to read DH parameters: " << ERR_error_string(ERR_get_error(), nullptr) << '\n';
        DH_free(temp);
        return 0;
    }
    temp = PEM_read_DHparams(params_file, &temp, NULL, NULL);
    if (temp == nullptr)
    {
        temp = DH_new();
        if (temp == nullptr)
        {
            std::cerr << "Failed to create DH object\n";
            return 0;
        }

        if (DH_generate_parameters_ex(temp, 2048, DH_GENERATOR_2, nullptr) != 1)
        {
            std::cerr << "Failed to generate DH parameters: " << ERR_error_string(ERR_get_error(), nullptr) << '\n';
            DH_free(temp);
            return 0;
        }

        int ret = PEM_write_DHparams(params_file, temp);
        if (ret == 1)
        {
            std::cerr << "Failed to writing DH parameters: " << ERR_error_string(ERR_get_error(), nullptr) << '\n';
            DH_free(temp);
            return 0;
        }
    }
    fclose(params_file);

    if (1 != EVP_PKEY_set1_DH(params, temp))
        handleErrors();

    DH_free(temp);

    printf("\n");
    printf("Generating ephemeral DH KeyPair\n");
    /* Create context for the key generation */
    EVP_PKEY_CTX *DHctx;
    if (!(DHctx = EVP_PKEY_CTX_new(params, NULL)))
        handleErrors();
    /* Generate a new key */
    EVP_PKEY *my_dhkey = NULL;
    if (1 != EVP_PKEY_keygen_init(DHctx))
        handleErrors();
    if (1 != EVP_PKEY_keygen(DHctx, &my_dhkey))
        handleErrors();

    /*write my public key into a file, so the other client can read it*/
    string my_pubkey_file_name;
    cout << "Please, type the PEM file that will contain your DH public key: ";
    getline(cin, my_pubkey_file_name);
    if (!cin)
    {
        cerr << "Error during input\n";
        exit(1);
    }
    FILE *p1w = fopen(my_pubkey_file_name.c_str(), "w");
    if (!p1w)
    {
        cerr << "Error: cannot open file '" << my_pubkey_file_name << "' (missing?)\n";
        exit(1);
    }
    PEM_write_PUBKEY(p1w, my_dhkey);
    fclose(p1w);
    string peer_pubkey_file_name;

    cout << "Please, type the PEM file that contains the peer's DH public key: ";
    getline(cin, peer_pubkey_file_name);
    if (!cin)
    {
        cerr << "Error during input\n";
        exit(1);
    }
    /*Load peer public key from a file*/
    FILE *p2r = fopen(peer_pubkey_file_name.c_str(), "r");
    if (!p2r)
    {
        cerr << "Error: cannot open file '" << peer_pubkey_file_name << "' (missing?)\n";
        exit(1);
    }
    EVP_PKEY *peer_pubkey = PEM_read_PUBKEY(p2r, NULL, NULL, NULL);
    fclose(p2r);
    if (!peer_pubkey)
    {
        cerr << "Error: PEM_read_PUBKEY returned NULL\n";
        exit(1);
    }

    printf("Deriving a shared secret\n");
    /*creating a context, the buffer for the shared key and an int for its length*/
    EVP_PKEY_CTX *derive_ctx;
    unsigned char *skey;
    size_t skeylen;
    derive_ctx = EVP_PKEY_CTX_new(my_dhkey, NULL);
    if (!derive_ctx)
        handleErrors();
    if (EVP_PKEY_derive_init(derive_ctx) <= 0)
        handleErrors();
    /*Setting the peer with its pubkey*/
    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pubkey) <= 0)
        handleErrors();
    /* Determine buffer length, by performing a derivation but writing the result nowhere */
    EVP_PKEY_derive(derive_ctx, NULL, &skeylen);
    /*allocate buffer for the shared secret*/
    skey = (unsigned char *)(malloc(int(skeylen)));
    if (!skey)
        handleErrors();
    /*Perform again the derivation and store it in skey buffer*/
    if (EVP_PKEY_derive(derive_ctx, skey, &skeylen) <= 0)
        handleErrors();
    printf("Here it is the shared secret: \n");
    BIO_dump_fp(stdout, (const char *)skey, skeylen);
    /*WARNING! YOU SHOULD NOT USE THE DERIVED SECRET AS A SESSION KEY!
     * IS COMMON PRACTICE TO HASH THE DERIVED SHARED SECRET TO OBTAIN A SESSION KEY.
     * IN NEXT LABORATORY LESSON WE ADDRESS HASHING!
     */
    // FREE EVERYTHING INVOLVED WITH THE EXCHANGE (not the shared secret tho)
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(peer_pubkey);
    EVP_PKEY_free(my_dhkey);
    EVP_PKEY_CTX_free(DHctx);
    EVP_PKEY_free(params);

    // SECOND PART: ENCRYTPION OF MY MESSAGE.

    int ret; // used for return values
    // read the file to encrypt from keyboard:
    string clear_file_name;
    cout << "Please, type the file to encrypt: ";
    getline(cin, clear_file_name);
    if (!cin)
    {
        cerr << "Error during input\n";
        exit(1);
    }
    // open the file to encrypt:
    FILE *clear_file = fopen(clear_file_name.c_str(), "rb");
    if (!clear_file)
    {
        cerr << "Error: cannot open file '" << clear_file_name << "' (file does not exist?)\n";
        exit(1);
    }

    // get the file size:
    // (assuming no failures in fseek() and ftell())
    fseek(clear_file, 0, SEEK_END);
    long int clear_size = ftell(clear_file);
    fseek(clear_file, 0, SEEK_SET);
    // read the plaintext from file:
    unsigned char *clear_buf = (unsigned char *)malloc(clear_size);
    if (!clear_buf)
    {
        cerr << "Error: malloc returned NULL (file too big?)\n";
        exit(1);
    }
    ret = fread(clear_buf, 1, clear_size, clear_file);
    if (ret < clear_size)
    {
        cerr << "Error while reading file '" << clear_file_name << "'\n";
        exit(1);
    }
    fclose(clear_file);

    // declare some useful variables:
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    int iv_len = EVP_CIPHER_iv_length(cipher);
    int block_size = EVP_CIPHER_block_size(cipher);

    // Assume key is the first 16 bytes of the shared secret (this is not the best thing to do).
    unsigned char *key = (unsigned char *)malloc(iv_len);
    memcpy(key, skey, iv_len);
    // Allocate memory for and randomly generate IV:
    unsigned char *iv = (unsigned char *)malloc(iv_len);
    // Seed OpenSSL PRNG
    RAND_poll();
    // Generate 16 bytes at random. That is my IV
    RAND_bytes((unsigned char *)&iv[0], iv_len);

    // check for possible integer overflow in (clear_size + block_size) --> PADDING!
    // (possible if the plaintext is too big, assume non-negative clear_size and block_size):
    if (clear_size > INT_MAX - block_size)
    {
        cerr << "Error: integer overflow (file too big?)\n";
        exit(1);
    }
    // allocate a buffer for the ciphertext:
    int enc_buffer_size = clear_size + block_size;
    unsigned char *cphr_buf = (unsigned char *)malloc(enc_buffer_size);
    if (!cphr_buf)
    {
        cerr << "Error: malloc returned NULL (file too big?)\n";
        exit(1);
    }

    // Create and initialise the context with used cipher, key and iv
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n";
        exit(1);
    }
    ret = EVP_EncryptInit(ctx, cipher, key, iv);
    if (ret != 1)
    {
        cerr << "Error: EncryptInit Failed\n";
        exit(1);
    }
    int update_len = 0; // bytes encrypted at each chunk
    int total_len = 0;  // total encrypted bytes

    // Encrypt Update: one call is enough because our file is small.
    ret = EVP_EncryptUpdate(ctx, cphr_buf, &update_len, clear_buf, clear_size);
    if (ret != 1)
    {
        cerr << "Error: EncryptUpdate Failed\n";
        exit(1);
    }
    total_len += update_len;

    // Encrypt Final. Finalize the encryption and adds the padding
    ret = EVP_EncryptFinal(ctx, cphr_buf + total_len, &update_len);
    if (ret != 1)
    {
        cerr << "Error: EncryptFinal Failed\n";
        exit(1);
    }
    total_len += update_len;
    int cphr_size = total_len;

    // delete the context and the plaintext from memory:
    EVP_CIPHER_CTX_free(ctx);
// Telling the compiler it MUST NOT optimize the following instruction.
// With optimization the memset would be skipped, because of the next free instruction.
#pragma optimize("", off)
    memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
    free(clear_buf);

    // write the IV and the ciphertext into a '.enc' file:
    string cphr_file_name = clear_file_name + ".enc";
    FILE *cphr_file = fopen(cphr_file_name.c_str(), "wb");
    if (!cphr_file)
    {
        cerr << "Error: cannot open file '" << cphr_file_name << "' (no permissions?)\n";
        exit(1);
    }

    ret = fwrite(iv, 1, EVP_CIPHER_iv_length(cipher), cphr_file);
    if (ret < EVP_CIPHER_iv_length(cipher))
    {
        cerr << "Error while writing the file '" << cphr_file_name << "'\n";
        exit(1);
    }

    ret = fwrite(cphr_buf, 1, cphr_size, cphr_file);
    if (ret < cphr_size)
    {
        cerr << "Error while writing the file '" << cphr_file_name << "'\n";
        exit(1);
    }

    fclose(cphr_file);
    cout << "File '" << clear_file_name << "' encrypted into file '" << cphr_file_name << "'\n";

    // deallocate buffers:
    free(cphr_buf);
    free(iv);

    // THIRD PART DECRYPTION OF PEER MESSAGE.

    // read the file to decrypt from keyboard:
    string peer_file_name;
    cout << "Please, type the file to decrypt: ";
    getline(cin, peer_file_name);
    if (!cin)
    {
        cerr << "Error during input\n";
        exit(1);
    }

    // open the file to decrypt:
    FILE *peer_file = fopen(peer_file_name.c_str(), "rb");
    if (!peer_file)
    {
        cerr << "Error: cannot open file '" << peer_file_name << "' (file does not exist?)\n";
        exit(1);
    }

    // get the file size:
    // (assuming no failures in fseek() and ftell())
    fseek(peer_file, 0, SEEK_END);
    long int peer_file_size = ftell(peer_file);
    fseek(peer_file, 0, SEEK_SET);

    // Allocate buffer for IV, ciphertext, plaintext
    unsigned char *peer_iv = (unsigned char *)malloc(iv_len);
    int peer_cphr_size = peer_file_size - iv_len;
    unsigned char *peer_msg_buf = (unsigned char *)malloc(peer_cphr_size);
    unsigned char *peer_clear_buf = (unsigned char *)malloc(peer_cphr_size);
    if (!peer_iv || !peer_msg_buf || !peer_clear_buf)
    {
        cerr << "Error: malloc returned NULL (file too big?)\n";
        exit(1);
    }

    // read the IV and the ciphertext from file:
    ret = fread(peer_iv, 1, iv_len, peer_file);
    if (ret < iv_len)
    {
        cerr << "Error while reading file '" << peer_file_name << "'\n";
        exit(1);
    }
    ret = fread(peer_msg_buf, 1, peer_cphr_size, peer_file);
    if (ret < peer_cphr_size)
    {
        cerr << "Error while reading file '" << peer_file_name << "'\n";
        exit(1);
    }
    fclose(peer_file);

    // Create and initialise the context
    EVP_CIPHER_CTX *peer_ctx;
    peer_ctx = EVP_CIPHER_CTX_new();
    if (!peer_ctx)
    {
        cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n";
        exit(1);
    }
    ret = EVP_DecryptInit(peer_ctx, cipher, key, peer_iv);
    if (ret != 1)
    {
        cerr << "Error: DecryptInit Failed\n";
        exit(1);
    }

    int peer_update_len = 0; // bytes decrypted at each chunk
    int peer_total_len = 0;  // total decrypted bytes

    // Decrypt Update: one call is enough because our ciphertext is small.
    ret = EVP_DecryptUpdate(peer_ctx, peer_clear_buf, &peer_update_len, peer_msg_buf, peer_cphr_size);
    if (ret != 1)
    {
        cerr << "Error: DecryptUpdate Failed\n";
        exit(1);
    }
    peer_total_len += peer_update_len;

    // Decrypt Final. Finalize the Decryption and adds the padding
    ret = EVP_DecryptFinal(peer_ctx, peer_clear_buf + peer_total_len, &peer_update_len);
    if (ret != 1)
    {
        cerr << "Error: DecryptFinal Failed\n";
        exit(1);
    }
    peer_total_len += peer_update_len;
    int peer_clear_size = peer_total_len;

    // delete the context from memory:
    EVP_CIPHER_CTX_free(peer_ctx);

    // write the plaintext into a '.dec' file:
    string peer_clear_file_name = peer_file_name + ".dec";
    FILE *peer_clear_file = fopen(peer_clear_file_name.c_str(), "wb");
    if (!peer_clear_file)
    {
        cerr << "Error: cannot open file '" << peer_clear_file_name << "' (no permissions?)\n";
        exit(1);
    }
    ret = fwrite(peer_clear_buf, 1, peer_clear_size, peer_clear_file);
    if (ret < peer_clear_size)
    {
        cerr << "Error while writing the file '" << peer_clear_file_name << "'\n";
        exit(1);
    }
    fclose(peer_clear_file);

    // Just out of curiosity, print on stdout the used IV retrieved from file.
    cout << "Used IV:" << endl;
    BIO_dump_fp(stdout, (const char *)peer_iv, iv_len);

// delete the plaintext from memory:
// Telling the compiler it MUST NOT optimize the following instruction.
// With optimization the memset would be skipped, because of the next free instruction.
#pragma optimize("", off)
    memset(peer_clear_buf, 0, peer_clear_size);
#pragma optimize("", on)
    free(peer_clear_buf);

    cout << "File '" << peer_file_name << "' decrypted into file '" << peer_clear_file_name << "', clear size is " << peer_clear_size << " bytes\n";

    // deallocate buffers:
    free(iv);
    free(peer_msg_buf);
    return 0;
}
