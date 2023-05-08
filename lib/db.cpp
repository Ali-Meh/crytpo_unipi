
#include <iostream>
#include <sqlite3.h>
#include <cstring>
#include "vector"

using namespace std;

// Define the struct for the client data
struct Client
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
    vector<Client> *clients = reinterpret_cast<vector<Client> *>(data);
    Client client;

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
Client getClientById(int id)
{
    Client client;
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
Client getClientByUsername(sqlite3 *db, const string &username)
{
    vector<Client> clients;
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

    if (clients.empty())
    {
        cerr << "Client not found" << endl;
        sqlite3_close(db);
        exit(1);
    }

    return clients[0];
}

// Function to insert a new client
void insertClient(sqlite3 *db, const Client &client)
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
}

// Define the function to update a client in the clients table
void updateClient(sqlite3 *db, const Client &client)
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

int main()
{
    // Pointer to SQLite connection
    sqlite3 *db;

    // Save the connection result
    int exit = 0;
    exit = sqlite3_open("SBA.db", &db);

    // Test if there was an error
    if (exit)
    {

        cout << "DB Open Error: " << sqlite3_errmsg(db) << endl;
    }
    else
    {

        cout << "Opened Database Successfully!" << endl;
    }

    Client c = Client{
        0,
        "ali",
        "password",
        "something",
        10000.10,
        0};

    insertClient(db, c);
    Client c2 = getClientByUsername(db, "ali");
    printf("%s==%s", c, c2);
    puts("idonko");

    // Close the connection
    sqlite3_close(db);

    return (0);
}