#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "init.cpp"

int cleanup_shutdown();
void prepare_asymmetric_enc();
void connect_db(const char *filename);

// Pointer to SQLite connection
sqlite3 *db;
// RSA *keypair;

int main(int argc, char *argv[])
{
    // prepare_asymmetric_enc();

    connect_db("lib/SBA.db");
    seed_db(db);

    return cleanup_shutdown();
}

int cleanup_shutdown()
{
    // Clean up
    // RSA_free(keypair);
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
