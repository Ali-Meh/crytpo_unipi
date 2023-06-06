#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <iostream>

//Function to simulate network send
void sendToClient(const BIGNUM *pubKey) {
    // Simulate sending public key to client
}

int main() {
    // Generate our own DH parameters
    DH *dh = DH_new();
    if(DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL) != 1) {
        std::cout << "Unable to generate DH parameters\n";
        return -1;
    }

    // Generate private and public keys
    if(DH_generate_key(dh) != 1) {
        std::cout << "Unable to generate keys\n";
        return -1;
    }

    const BIGNUM *pub_key, *priv_key;
    DH_get0_key(dh, &pub_key, &priv_key);

    sendToClient(pub_key);

    // Here, you would wait to receive client's public key and HMAC'd message
    // Then compute shared secret and verify HMAC
    
    return 0;
}
