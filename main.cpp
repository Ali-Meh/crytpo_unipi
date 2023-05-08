#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "lib/RSA.cpp"

int cleanup_shutdown();
void prepare_asymmetric_enc();

RSA *keypair;

int main(int argc, char *argv[])
{
    prepare_asymmetric_enc();

    return cleanup_shutdown();
}

int cleanup_shutdown()
{
    // Clean up
    RSA_free(keypair);
    return 0;
}

// will generate or load up the prv/pub keys for asymmetric encryption
void prepare_asymmetric_enc()
{
    keypair = load_private_key();
    if (keypair == NULL)
    {
        keypair = generate_keypair();
        int ret = save_keypair_to_file(keypair);
        if (ret != 1)
        {
            perror("main: Couldn't find or generate pub/prv keys.");
        }
    }
}