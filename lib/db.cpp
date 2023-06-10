
#include <iostream>
#include <sqlite3.h>
#include <cstring>
#include <sstream>
#include "vector"
#include "const.h"

using namespace std;

struct sba_transaction_t
{
    int id;
    int userId;
    string encTransaction; // (user, amount, timestamp).
};

constexpr char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
string base64_encode(const string &input)
{
    ostringstream encoded;
    int val = 0;
    int valb = -6;
    for (char c : input)
    {
        val = (val << 8) + static_cast<unsigned char>(c);
        valb += 8;
        while (valb >= 0)
        {
            encoded << base64_chars[(val >> valb) & 0x3F];
            valb -= 6;
        }
    }

    if (valb > -6)
        encoded << base64_chars[((val << 8) >> (valb + 8)) & 0x3F];

    while (encoded.tellp() % 4 != 0)
        encoded << '=';

    return encoded.str();
}

std::string base64_decode(const std::string &input)
{

    std::string decoded;
    int val = 0;
    int valb = -8;
    for (char c : input)
    {
        if (c == '=')
            break;
        if (c >= 'A' && c <= 'Z')
            c -= 'A';
        else if (c >= 'a' && c <= 'z')
            c = c - 'a' + 26;
        else if (c >= '0' && c <= '9')
            c = c - '0' + 52;
        else if (c == '+')
            c = 62;
        else if (c == '/')
            c = 63;
        else
            continue;

        val = (val << 6) + c;
        valb += 6;
        if (valb >= 0)
        {
            decoded.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    return decoded;
}

string serializeTransactionsToString(const vector<sba_transaction_t> &transactions)
{
    ostringstream oss;
    for (const auto &transaction : transactions)
    {
        oss << transaction.id << ','
            << transaction.userId << ','
            << transaction.encTransaction << '\n';
    }

    return oss.str();
}

vector<sba_transaction_t> deserializeTransactionsFromString(const string &serialized)
{
    vector<sba_transaction_t> transactions;

    istringstream iss(serialized);
    string line;
    while (getline(iss, line))
    {
        istringstream lineStream(line);
        string field;
        getline(lineStream, field, ',');
        int id = stoi(field);
        getline(lineStream, field, ',');
        int userId = stoi(field);
        getline(lineStream, field, ',');
        string encTransaction = field;

        sba_transaction_t transaction;
        transaction.id = id;
        transaction.userId = userId;
        transaction.encTransaction = encTransaction;

        transactions.push_back(transaction);
    }

    return transactions;
}

// Function to handle errors
static int errorHandler(void *data, int errorCode, const char *errorMessage)
{
    cerr << "Error (" << errorCode << "): " << errorMessage << endl;
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
        cerr << "Error preparing update statement: " << sqlite3_errmsg(db) << endl;
        return rc;
    }

    sqlite3_bind_double(stmt, 1, amount);
    sqlite3_bind_int(stmt, 2, transaction.userId);

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE)
    {
        // Handle error executing the first update statement
        cerr << "Error deducting from senders balance: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        return rc;
    }

    sqlite3_reset(stmt);

    rc = sqlite3_prepare_v2(db, "UPDATE clients SET Balance = Balance + ? WHERE id = ?;", -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        // Handle error preparing the second update statement
        cerr << "Error preparing update statement: " << sqlite3_errmsg(db) << endl;
        return rc;
    }

    sqlite3_bind_double(stmt, 1, amount);
    sqlite3_bind_int(stmt, 2, receiver);

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE)
    {
        // Handle error executing the second update statement
        cerr << "Error adding to recievers balance: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        return rc;
    }

    sqlite3_reset(stmt);

    rc = sqlite3_prepare_v2(db, "INSERT INTO Transactions (user_id, enc_transaction) VALUES (?, ?);", -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        // Handle error preparing the second update statement
        cerr << "Error preparing insert statement: " << sqlite3_errmsg(db) << endl;
        return rc;
    }

    // Bind values to prepared statement
    sqlite3_bind_int(stmt, 1, transaction.userId);
    sqlite3_bind_blob(stmt, 2, transaction.encTransaction.data(), transaction.encTransaction.size(), SQLITE_STATIC);

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE)
    {
        // Handle error executing the second update statement
        cerr << "Error inserting transaction: " << sqlite3_errmsg(db) << endl;
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
// Define transaction callback function for SELECT queries
static int trxSelectCallback(void *data, int argc, char **argv, char **azColName)
{
    vector<sba_transaction_t> *trxs = reinterpret_cast<vector<sba_transaction_t> *>(data);
    sba_transaction_t trx;

    for (int i = 0; i < argc; i++)
    {
        string colName = azColName[i];
        string colValue = argv[i] ? argv[i] : "";

        if (colName == "Id")
        {
            trx.id = stoi(colValue);
        }
        else if (colName == "user_id")
        {
            trx.userId = stoi(colValue);
        }
        else if (colName == "enc_transaction")
        {
            trx.encTransaction = colValue;
        }
    }

    trxs->push_back(trx);
    return 0;
}

// Function to retrieve a transaction by ID
vector<sba_transaction_t> getTransactionsById(sqlite3 *db, int userId, int limit = TRANSACTION_LIMIT)
{
    vector<sba_transaction_t> trxs;
    string sql = "SELECT * FROM Transactions WHERE user_id = '" + to_string(userId) + "'" + " order by Id desc limit " + to_string(limit);

    char *errorMsg = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), trxSelectCallback, &trxs, &errorMsg);

    if (rc != SQLITE_OK)
    {
        cerr << "Error querying database: " << errorMsg << endl;
        sqlite3_free(errorMsg);
        sqlite3_close(db);
        exit(1);
    }

    return trxs;
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
    string sql = "UPDATE clients SET username = ?, password = ?, pubkey = ?, balance = ?, nonce = ? WHERE id = ?";

    // Create a prepared statement object
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        cerr << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
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
        cerr << "Error executing statement: " << sqlite3_errmsg(db) << endl;
        return;
    }

    // Finalize the statement
    sqlite3_finalize(stmt);

    cout << "Client " << client.id << " updated successfully!" << endl;
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
