
#include <iostream>
#include <sqlite3.h>
#include <cstring>
#include "vector"

using namespace std;

struct sba_transaction_t
{
    int id;
    int userId;
    string encTransaction; // (user, amount, timestamp).
};

// Function to handle errors
static int errorHandler(void *data, int errorCode, const char *errorMessage)
{
    std::cerr << "Error (" << errorCode << "): " << errorMessage << std::endl;
    return 0;
}

// Function to Transfer amounts between user accounts and
int transferToReceiver(sqlite3 *db, const sba_transaction_t &transaction, int receiver, double amount)
{
    sqlite3_stmt *stmt;

    int rc = sqlite3_exec(db, "BEGIN;", 0, 0, 0);

    if (rc != SQLITE_OK)
    {
        // Handle error beginning transaction
        return rc;
    }

    rc = sqlite3_prepare_v2(db, "UPDATE clients SET Balance = Balance - ? WHERE id = ?;", -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        // Handle error preparing the first update statement
        std::cerr << "Error preparing update statement: " << sqlite3_errmsg(db) << std::endl;
        return rc;
    }

    sqlite3_bind_double(stmt, 1, amount);
    sqlite3_bind_int(stmt, 2, transaction.userId);

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE)
    {
        // Handle error executing the first update statement
        std::cerr << "Error deducting from senders balance: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return rc;
    }

    sqlite3_reset(stmt);

    rc = sqlite3_prepare_v2(db, "UPDATE clients SET Balance = Balance + ? WHERE id = ?;", -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        // Handle error preparing the second update statement
        std::cerr << "Error preparing update statement: " << sqlite3_errmsg(db) << std::endl;
        return rc;
    }

    sqlite3_bind_double(stmt, 1, amount);
    sqlite3_bind_int(stmt, 2, receiver);

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE)
    {
        // Handle error executing the second update statement
        std::cerr << "Error adding to recievers balance: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return rc;
    }

    sqlite3_reset(stmt);

    rc = sqlite3_prepare_v2(db, "INSERT INTO Transactions (user_id, enc_transaction) VALUES (?, ?);", -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        // Handle error preparing the second update statement
        std::cerr << "Error preparing insert statement: " << sqlite3_errmsg(db) << std::endl;
        return rc;
    }

    // Bind values to prepared statement
    sqlite3_bind_int(stmt, 1, transaction.userId);
    sqlite3_bind_blob(stmt, 2, transaction.encTransaction.data(), transaction.encTransaction.size(), SQLITE_STATIC);

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE)
    {
        // Handle error executing the second update statement
        std::cerr << "Error inserting transaction: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return rc;
    }

    rc = sqlite3_exec(db, "COMMIT;", 0, 0, 0);

    if (rc != SQLITE_OK)
    {
        // Handle error committing the transaction
        return rc;
    }

    sqlite3_finalize(stmt);
    return SQLITE_OK;
}

// Function to retrieve a transaction by ID
sba_transaction_t getTransactionById(sqlite3 *db, int id)
{
    sba_transaction_t trx;
    sqlite3_stmt *stmt;
    const char *query = "SELECT * FROM Transactions WHERE Id = ?";

    if (sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL) != SQLITE_OK)
    {
        std::cerr << "Error preparing select statement: " << sqlite3_errmsg(db) << std::endl;
        return trx;
    }

    // Bind value to prepared statement
    sqlite3_bind_int(stmt, 1, id);

    // Execute statement
    if (sqlite3_step(stmt) != SQLITE_ROW)
    {
        std::cerr << "Error selecting transaction: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return trx;
    }

    // Create transaction object from result
    // trx = new sba_transaction_t;
    trx.id = sqlite3_column_int(stmt, 0);
    trx.userId = sqlite3_column_int(stmt, 1);
    trx.encTransaction = (char *)sqlite3_column_blob(stmt, 2);

    sqlite3_finalize(stmt);
    return trx;
}

// Define the struct for the client data
struct sba_client_t
{
    int id;
    string username;
    string password;
    string pubkey;
    double balance;
    int nonce;
};

// Define the callback function for SELECT queries
static int selectCallback(void *data, int argc, char **argv, char **azColName)
{
    vector<sba_client_t> *clients = reinterpret_cast<vector<sba_client_t> *>(data);
    sba_client_t client;

    for (int i = 0; i < argc; i++)
    {
        string colName = azColName[i];
        string colValue = argv[i] ? argv[i] : "";

        if (colName == "id")
        {
            client.id = stoi(colValue);
        }
        else if (colName == "username")
        {
            client.username = colValue;
        }
        else if (colName == "password")
        {
            client.password = colValue;
        }
        else if (colName == "pubkey")
        {
            client.pubkey = colValue;
        }
        else if (colName == "Balance")
        {
            client.balance = stod(colValue);
        }
        else if (colName == "nonce")
        {
            client.nonce = stoi(colValue);
        }
    }

    clients->push_back(client);
    return 0;
}

// Function to get client information by ID
sba_client_t getClientById(int id)
{
    sba_client_t client;
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;

    rc = sqlite3_open("test.db", &db);

    if (rc)
    {
        cout << "Can't open database: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return client;
    }

    string sql = "SELECT * FROM clients WHERE id=" + to_string(id) + ";";
    const char *data = "Callback function called";

    rc = sqlite3_exec(db, sql.c_str(), selectCallback, (void *)data, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        cout << "SQL error: " << zErrMsg << endl;
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return client;
    }

    sqlite3_stmt *stmt;

    rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);

    if (rc == SQLITE_OK)
    {
        rc = sqlite3_step(stmt);

        if (rc == SQLITE_ROW)
        {
            client.id = sqlite3_column_int(stmt, 0);
            client.username = (char *)sqlite3_column_text(stmt, 1);
            client.password = (char *)sqlite3_column_text(stmt, 2);
            client.pubkey = (char *)sqlite3_column_text(stmt, 3);
            client.balance = sqlite3_column_double(stmt, 4);
            client.nonce = sqlite3_column_int(stmt, 5);
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return client;
}
// Function to get a single client by username
vector<sba_client_t> getClientByUsername(sqlite3 *db, const string &username)
{
    vector<sba_client_t> clients;
    string sql = "SELECT * FROM clients WHERE username = '" + username + "'";

    char *errorMsg = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), selectCallback, &clients, &errorMsg);

    if (rc != SQLITE_OK)
    {
        cerr << "Error querying database: " << errorMsg << endl;
        sqlite3_free(errorMsg);
        sqlite3_close(db);
        exit(1);
    }

    // if (clients.empty())
    // {
    //     cerr << "Client not found" << endl;
    //     sqlite3_close(db);
    //     exit(1);
    // }

    return clients;
}

// Function to insert a new client
int insertClient(sqlite3 *db, const sba_client_t &client)
{
    string sql = "INSERT INTO clients (username, password, pubkey, Balance, nonce) VALUES ('" + client.username + "', '" + client.password + "', '" + client.pubkey + "', " + to_string(client.balance) + ", " + to_string(client.nonce) + ")";

    char *errorMsg = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errorMsg);

    if (rc != SQLITE_OK)
    {
        cerr << "Error inserting into database: " << errorMsg << endl;
        sqlite3_free(errorMsg);
        sqlite3_close(db);
        exit(1);
    }

    return sqlite3_last_insert_rowid(db);
}

// Define the function to update a client in the clients table
void updateClient(sqlite3 *db, const sba_client_t &client)
{
    // Construct the SQL query string with placeholders for the values
    std::string sql = "UPDATE clients SET username = ?, password = ?, pubkey = ?, balance = ?, nonce = ? WHERE id = ?";

    // Create a prepared statement object
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        std::cerr << "Error preparing statement: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    // Bind the values to the prepared statement
    sqlite3_bind_text(stmt, 1, client.username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, client.password.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, client.pubkey.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 4, client.balance);
    sqlite3_bind_int(stmt, 5, client.nonce);
    sqlite3_bind_int(stmt, 6, client.id);

    // Execute the statement
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        std::cerr << "Error executing statement: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    // Finalize the statement
    sqlite3_finalize(stmt);

    std::cout << "Client " << client.id << " updated successfully!" << std::endl;
}

sqlite3 *connect(string file = "SBA.db")
{
    sqlite3 *db;
    int exit = 0;
    exit = sqlite3_open(file.data(), &db);
    if (exit)
    {

        cout << "DB Open Error: " << sqlite3_errmsg(db) << endl;
    }
    else
    {

        cout << "Opened Database Successfully!" << endl;
    }
    return db;
}

// int main()
// {
//     // Pointer to SQLite connection
//     sqlite3 *db;

//     // Save the connection result
//     int exit = 0;
//     exit = sqlite3_open("SBA.db", &db);

//     // Test if there was an error
//     if (exit)
//     {

//         cout << "DB Open Error: " << sqlite3_errmsg(db) << endl;
//     }
//     else
//     {

//         cout << "Opened Database Successfully!" << endl;
//     }

//     sba_transaction_t c = sba_transaction_t{
//         0,
//         1,
//         (char *)"enc_password"};

//     c.id = insertTransaction(db, c);
//     c.encTransaction = "not_enc_password";
//     printf("updated %d: %d\n", c.id, updateTransaction(db, c));
//     sba_transaction_t c2 = getTransactionById(db, 18);
//     printf("%s==%s\n", c.encTransaction.data(), c2.encTransaction.data());
//     puts("idk");

//     // sba_client_t c = sba_client_t{
//     //     0,
//     //     "ali",
//     //     "password",
//     //     "something",
//     //     10000.10,
//     //     0};

//     // insertClient(db, c);
//     // sba_client_t c2 = getClientByUsername(db, "ali");
//     // printf("%s==%s", c, c2);
//     // puts("idonko");

//     // Close the connection
//     sqlite3_close(db);

//     return (0);
// }