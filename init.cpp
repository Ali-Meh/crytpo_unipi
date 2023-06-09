#include "lib/EC.cpp"
#include "lib/RSA.cpp"
#include "lib/db.cpp"
#include "lib/hash.cpp"

void seed_db(sqlite3 *db)
{
    RSA *keypair;

    // Initialize an array of sba_client_t with 10 elements
    sba_client_t clients[10];

    // Seed data
    clients[0] = {1001, "a", "a", "", 5000.0, 1};
    clients[1] = {1002, "jane", "pa$$word", "", 10000.0, 2};
    clients[2] = {1003, "bob", "123456", "", 7500.0, 3};
    clients[3] = {1004, "sara", "ilovecake", "", 2500.0, 4};
    clients[4] = {1005, "michael", "password1", "", 15000.0, 5};
    clients[5] = {1006, "elizabeth", "qwerty123", "", 9000.0, 6};
    clients[6] = {1007, "will", "freshprince", "", 20000.0, 7};
    clients[7] = {1008, "chris", "kisskiss", "", 3500.0, 8};
    clients[8] = {1009, "amanda", "soccermom", "", 12000.0, 9};
    clients[9] = {1010, "steven", "letmein", "", 8000.0, 10};

    vector<sba_client_t> client = getClientByUsername(db, clients[0].username);
    if (!client.empty())
    {
        cout << "no need to seed, it's already there." << endl;
        return;
    }

    string ext = ".pem";
    string key_path = "keys/";

    // insert the seed data
    for (int i = 0; i < 10; i++)
    {
        clients[i].password = hash_password(clients[i].password);
        // Generate a new EC keypair
        keypair = rsa::generate_keypair();
        clients[i].pubkey = rsa::pubkey_tostring(keypair);
        int id = insertClient(db, clients[i]);

        rsa::save_keypair_to_file(keypair, (key_path + "sc" + to_string(id) + ext).c_str(), (key_path + "pc" + to_string(id) + ext).c_str());
        RSA_free(keypair);
    }

    // server keypair
    EC_KEY *skeypair = generateECDHEC_KEY();
    save_keypair_to_file(skeypair, (key_path + "server_sec" + ext).c_str(), (key_path + "server_pub" + ext).c_str());
    EC_KEY_free(skeypair);

    cout << "seed data to db complete." << endl;
}
