#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "lib/RSA.cpp"
#include "lib/db.cpp"
#include "lib/hash.cpp"

int cleanup_shutdown();
void prepare_asymmetric_enc();
void connect_db(const char *filename);

// Pointer to SQLite connection
sqlite3 *db;
RSA *keypair;

int main(int argc, char *argv[])
{
    // prepare_asymmetric_enc();

    connect_db("lib/SBA.db");

    // Initialize an array of sba_client_t with 10 elements
    sba_client_t clients[10];

    // Seed data
    clients[0] = {1001, "john_doe", "p@ssw0rd", "ssh-rsa pubkey", 5000.0, 1};
    clients[1] = {1002, "jane_doe", "pa$$word", "ssh-rsa pubkey", 10000.0, 2};
    clients[2] = {1003, "bob_smith", "123456", "ssh-rsa pubkey", 7500.0, 3};
    clients[3] = {1004, "sara_lee", "ilovecake", "ssh-rsa pubkey", 2500.0, 4};
    clients[4] = {1005, "michael_jones", "password1", "ssh-rsa pubkey", 15000.0, 5};
    clients[5] = {1006, "elizabeth_wang", "qwerty123", "ssh-rsa pubkey", 9000.0, 6};
    clients[6] = {1007, "will_smith", "freshprince", "ssh-rsa pubkey", 20000.0, 7};
    clients[7] = {1008, "chris_brown", "kisskiss", "ssh-rsa pubkey", 3500.0, 8};
    clients[8] = {1009, "amanda_wilson", "soccermom", "ssh-rsa pubkey", 12000.0, 9};
    clients[9] = {1010, "steven_nguyen", "letmein", "ssh-rsa pubkey", 8000.0, 10};

    // Print the seed data
    for (int i = 0; i < 10; i++)
    {
        clients[i].password = hash_password(clients[i].password);
        insertClient(db, clients[i]);
    }

    return cleanup_shutdown();
}

int cleanup_shutdown()
{
    // Clean up
    RSA_free(keypair);
    return 0;
}

// will generate or load up the prv/pub keys for asymmetric encryption
void connect_db(const char *filename = "SBA.db")
{
    // Save the connection result
    int exit = 0;
    exit = sqlite3_open(filename, &db);

    // Test if there was an error
    if (exit)
    {

        cout << "DB Open Error: " << sqlite3_errmsg(db) << endl;
    }
    else
    {

        cout << "Opened Database Successfully!" << endl;
    }
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