#ifndef __FUNCTIONS_H
#define __FUNCTIONS_H

//necessary libraries
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>  // for open
#include <unistd.h> // for close
#include <pthread.h>
#include <iostream>
#include <string>
#include <sys/time.h>
#include "stdio.h"
#include <sqlite3.h>

//to hash the password
#include "sha256.h"
//to encode and decode messages
#include "base64.h"

using namespace std;

#define TRUE 1
#define ERROR -1

#define MAINSERVERPORT 8080 // The port number for the Main Server
#define SERVERGATEPORT 8888 // The port number for the Server Gate
#define NOOFCLIENTS 30
#define NOOFTHREADS 30
#define BUFFERSIZE 8192

FILE *errorFile;
FILE *logFile;

char buffer[BUFFERSIZE] = {0};
char option[BUFFERSIZE] = {0};
string genUsername;
string genPassword;
string registerName, registerPassword;
char token[BUFFERSIZE] = {0};
string loginUsername;
string loginPassword;
string authToken;
string genToken;
string generalUser;
string generalPassword;


int clientCount = 0;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

struct client{ // client structure to determine its credentials
    string username;
    string password;
    int index;
    int sockID;
    struct sockaddr_in clientAddr;
    int len = sizeof(clientAddr);
    string authToken;
};

struct client Client[NOOFCLIENTS];
pthread_t serverThread[NOOFTHREADS];

//Functions
int createSocket();
struct sockaddr_in defineAddress(int PORTNUMBER);
void bindSocket(int anySocket, struct sockaddr_in anyAddress);
void listenForConnections(int anySocket);
int acceptConnections(int anySocket, struct sockaddr_in anyAddress);
void connectToServerGate(int anySocket, struct sockaddr_in anyAddress);
void connectToMainServer(int anySocket, struct sockaddr_in anyAddress);
bool menuFunction(char option[BUFFERSIZE], int anySocket);
void registerUser();
bool logIn(int anySocket);
void setUserInfo(string loginUsername, string loginPassword);
const char *getCurrentTime();
void sendUsername(int anySocket, string usern);
void logOperations(char *LogString);
void logErrors(char *errorString, int errNo);
string generateToken();
string recvToken(int anySocket);
void sendToken(int anySocket);
void controlRecvToken(int anySocket);
bool controlToken(string authenticationToken);

void saveUserToDB(string registerUsername, string registerPassword){
    sqlite3 *DB;
    char *messaggeError;
    int exit = 0;

    exit = sqlite3_open("SERVER.db", &DB);

    if (exit)
    {
        cerr << "Error open DB " << sqlite3_errmsg(DB) << endl;
    }
    else
        cout << "Opened Database Successfully!" << endl;

    string sql1 = "CREATE TABLE IF NOT EXISTS registeredUsers ("
                  "USERNAME        STRING, "
                  "PASSWORD         STRING );";
    int exit2 = 0;
    exit2 = sqlite3_exec(DB, sql1.c_str(), NULL, 0, &messaggeError);

    if (exit2 != SQLITE_OK)
    {
        cerr << "Error Create Table" << endl;
        sqlite3_free(messaggeError);
    }
    else
        cout << "Table created Successfully" << endl;

    string sql2("INSERT INTO registeredUsers (USERNAME,PASSWORD) VALUES ('" + registerUsername + "','" + registerPassword + "');");

    int exit3 = 0;
    exit3 = sqlite3_exec(DB, sql2.c_str(), NULL, 0, &messaggeError);
    if (exit3 != SQLITE_OK)
    {
        cerr << "Error Insert" << endl;
        sqlite3_free(messaggeError);
    }
    else
        cout << "Records created Successfully!" << endl;

    sqlite3_close(DB);
}

void saveHistoryToDB(string messageSent, string timeOfDay){
    sqlite3 *DB;
    char *messaggeError;
    int exit = 0;

    exit = sqlite3_open("SERVER.db", &DB);

    if (exit)
    {
        cerr << "Error open DB " << sqlite3_errmsg(DB) << endl;
    }

    string sql1 = "CREATE TABLE IF NOT EXISTS messageHistory ("
                  "MESSAGE        STRING, "
                  "TIMEOFOCCURENCE         STRING );";
    int exit2 = 0;
    exit2 = sqlite3_exec(DB, sql1.c_str(), NULL, 0, &messaggeError);

    if (exit2 != SQLITE_OK)
    {
        cerr << "Error Create Table" << endl;
        sqlite3_free(messaggeError);
    }

    string sql2("INSERT INTO messageHistory (MESSAGE,TIMEOFOCCURENCE) VALUES ('" + messageSent + "','" + timeOfDay + "');");

    int exit3 = 0;
    exit3 = sqlite3_exec(DB, sql2.c_str(), NULL, 0, &messaggeError);
    if (exit3 != SQLITE_OK)
    {
        cerr << "Error Insert" << endl;
        sqlite3_free(messaggeError);
    }

    sqlite3_close(DB);
}

void showHistory(int clientSocket){
    sqlite3 *DB;
    char *messaggeError;
    int exit = 0;
    exit = sqlite3_open("SERVER.db", &DB);
    if (exit)
    {
        cerr << "Error open DB " << sqlite3_errmsg(DB) << endl;
    }
    sqlite3_stmt *getMessages;
    char* tblN;
     sqlite3_prepare(DB, "SELECT MESSAGE FROM messageHistory", -1, &getMessages, NULL);
     
     while (sqlite3_step(getMessages) == SQLITE_ROW)
    {
        tblN = (char*)sqlite3_column_text(getMessages, 0);
        send(clientSocket, tblN, BUFFERSIZE, 0);
    }
    sqlite3_close(DB);
}

int callbackUsername(void *data, int argc, char **argv, char **azColName){
    int i;

    for (i = 0; i < argc; i++)
    {
        if (argv[i] != "")
        {
            generalUser = argv[i];
            return 0;
        }
        else
            return 1;
    }
}

int callbackPassword(void *data, int argc, char **argv, char **azColName){
    int i;
    for (i = 0; i < argc; i++)
    {
        if (argv[i] != "")
        {
            generalPassword = argv[i];
            return 0;
        }
        else
            return 1;
    }
}

bool checkDB(int anySocket){
    sqlite3 *DB;
    char *messaggeError;
    int exit = 0;
    string data("CALLBACK FUNCTION");
    string loginUsername;
    string loginPassword;
    string inputHash;

    cout << "Enter username :";
    cin >> loginUsername;
    loginPassword = getpass("Enter password: ");
    inputHash = sha256(loginPassword);

    exit = sqlite3_open("SERVER.db", &DB);

    if (exit)
    {
        cerr << "Error open DB " << sqlite3_errmsg(DB) << endl;
    }

    string sql("SELECT USERNAME FROM registeredUsers WHERE USERNAME = '" + loginUsername + "'");

    int exit3;
    exit3 = sqlite3_exec(DB, sql.c_str(), callbackUsername, (void *)data.c_str(), &messaggeError);
    if (exit3 == 0)
    {

        if (generalUser == loginUsername)
        {
            string sql2("SELECT PASSWORD FROM registeredUsers WHERE PASSWORD = '" + inputHash + "'");
            int exit4;
            exit4 = sqlite3_exec(DB, sql2.c_str(), callbackPassword, (void *)data.c_str(), &messaggeError);
            if (generalPassword == inputHash)
            {
                setUserInfo(loginUsername, loginPassword);
                sendUsername(anySocket, genUsername);
                sqlite3_close(DB);
                
                return 1;
            }
        }
        else
        {
            cout << "username doesn't exist" << endl;
            return 0;
        }
    }
    else
    {
        cout << "Username doesn't exist." << endl;
        sqlite3_close(DB);
        return 0;
    }
}

static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
static inline bool is_base64(unsigned char c){
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(unsigned char const *bytes_to_encode, unsigned int in_len){
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--)
    {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';
    }

    return ret;
}

std::string base64_decode(std::string const &encoded_string){
    size_t in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_]))
    {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i == 4)
        {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]) & 0xff;

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i)
    {
        for (j = 0; j < i; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]) & 0xff;

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

        for (j = 0; (j < i - 1); j++)
            ret += char_array_3[j];
    }

    return ret;
}

void logErrors(char *errorString, int errNo){ //writes errors to a txt file.
    errorFile = fopen("errorLog.txt", "ab");
    fprintf(errorFile, "%s: %s , %s\n", errorString, strerror(errNo), getCurrentTime());
    fclose(errorFile);
}

void logOperations(char *LogString){
    logFile = fopen("ServerLog.txt", "ab");
    fprintf(logFile, "%s, %s", LogString, getCurrentTime());
    fclose(logFile);
}

int createSocket(){ // creates IPv4 socket
    int newSocket;
    int opt = TRUE;
    if ((newSocket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        cerr << "socket failed";
        logErrors("an error occured while creating a socket", errno);
        exit(EXIT_FAILURE);
    }
    else
    {
        // Setsockopt function revents error such as; “address already in use” and orcefully attach the socket to the intended port
        if (setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0)
        {
            cerr << "[-] Setsockopt Error" << endl; // Inform the user about setsockopt function error
            exit(EXIT_FAILURE);
        }
        logOperations("Created socket");
        return newSocket;
    }
}

struct sockaddr_in defineAddress(int PORTNUMBER){ // defines an address in a given port number
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORTNUMBER);
    logOperations("Socket address info is defined.");
    return address;
}

void bindSocket(int anySocket, struct sockaddr_in anyAddress){ // bind the socket to the given port
    if (bind(anySocket, (struct sockaddr *)&anyAddress, sizeof(anyAddress)) < 0)
    {
        cerr << "bind";
        logErrors("an error occured while binding", errno);
        exit(EXIT_FAILURE);
    }
}

void listenForConnections(int anySocket){ // listen for connections from given socket
    if (listen(anySocket, SOMAXCONN) < 0)
    {
        cerr << "listen";
        logErrors("an error occured while listening", errno);
        exit(EXIT_FAILURE);
    }
}

int acceptConnections(int anySocket, struct sockaddr_in anyAddress){ // accept connection to given socket from the given address
    int addrlen = sizeof(anyAddress);
    int newSocket;
    if ((newSocket = accept(anySocket, (struct sockaddr *)&anyAddress, (socklen_t *)&addrlen)) < 0)
    {
        cerr << "accept";
        logErrors("an error occured while accepting", errno);
        exit(EXIT_FAILURE);
    }

    return newSocket;
}

int acceptConnection(int server, struct client *client, int clientCount){

    int connectionSocket = accept(server, (struct sockaddr *)&client[clientCount].clientAddr, (socklen_t *)&client[clientCount].len); //accept an incoming connection on a listening socket.
    if (connectionSocket == ERROR)
    {
        cerr << "an error occured while accepting";
        logErrors("an error occured while accepting", errno);
        exit(EXIT_FAILURE);
    }

    return connectionSocket;
}

void connectToServerGate(int anySocket, struct sockaddr_in anyAddress){
    int valread;

    if (connect(anySocket, (struct sockaddr *)&anyAddress, sizeof(anyAddress)) < 0)
    {
        cerr << "connection failed1";
        logErrors("an error occured while connecting to server", errno);
        exit(EXIT_FAILURE);
    }
    else
    {
        cout << "Choose what to do:\n 1.Register\t 2.Login\t 3.Exit" << endl;
    }
}

void connectToMainServer(int anySocket, struct sockaddr_in anyAddress){
    if (connect(anySocket, (struct sockaddr *)&anyAddress, sizeof(anyAddress)) < 0)
    {
        cerr << "connection failed";
        logErrors("an error occured while connecting to server", errno);
        exit(EXIT_FAILURE);
    }

    cout << "Directing you to the Main Server ... " << endl;
}

bool menuFunction(char option[BUFFERSIZE], int anySocket){
    cin >> option;
    if (option[0] == '1')
    {
        registerUser();
    }
    else if (option[0] == '2')
    {
        if (checkDB(anySocket) == 1)
        {
            return 1;
        }
    }
    else if (option[0] == '3')
    {
        exit(EXIT_FAILURE);
    }
    else
    {
        cout << "Wrong decision";
        exit(EXIT_FAILURE);
    }
}

void registerUser(){
    string hashPassword;
    cout << "New Username :";
    cin >> registerName;

    registerPassword = getpass("New password: ");
    hashPassword = sha256(registerPassword);
    saveUserToDB(registerName, hashPassword);
    cout << "New user registration completed !\n";
    cout << "Run the program again and log in to server !";
    exit(EXIT_FAILURE);
}


void setUserInfo(string loginUsername, string loginPassword){
    genUsername = loginUsername;
    genPassword = loginPassword;
}

void sendUsername(int anySocket, string usern){
    int n = usern.length();
    char char_array[n + 1];
    strcpy(char_array, usern.c_str());
    int bytesSent = send(anySocket, char_array, strlen(char_array), 0);
}

string recvToken(int anySocket){
    string tok;
    int bytesRecv = read(anySocket, buffer, sizeof(buffer));
    tok = buffer;
    return tok;
}

string recvUsername(int anySocket, string serverSideUsername){
    int bytesRecv = read(anySocket, buffer, sizeof(buffer));
    while (1)
    {
        if (bytesRecv > 0)
        {
            serverSideUsername = buffer;
            return serverSideUsername;
        }
        else
        {
            continue;
        }
    }
}

void sendToken(int anySocket){
    authToken = generateToken();
    int n = authToken.length();
    char tokenChar[n + 1];
    strcpy(tokenChar, authToken.c_str());
    int bytesSent = send(anySocket, tokenChar, strlen(tokenChar), 0);
}

void *sendAndReceive(void *ClientDetail) //Server thread to handle send and recieve functions between clients.
                                         // Takes client struct as parameter
                                         {
    struct client *clientDetail = (struct client *)ClientDetail;
    string authentication = clientDetail->authToken;
    int index = clientDetail->index;
    int clientSocket = clientDetail->sockID;
    int n = clientDetail->username.length();

    char char_array[n + 1];

    strcpy(char_array, clientDetail->username.c_str());

    cout << "[+] " << char_array << " connected to server ! " << endl;
    cout << " Client Count = " << clientCount << endl;

    while (1)
    {

        char data[BUFFERSIZE];
        int read = recv(clientSocket, data, BUFFERSIZE, 0); //Read command from client(SEND,LIST).
        data[read] = '\0';                                  // '\0' is used for ending string.

        char output[BUFFERSIZE];
        //if the data is "LIST", server sends list of other clients.
        if (strcmp(data, "LIST") == 0)
        {

            int offset = 0;
            for (int i = 0; i < clientCount; i++)
            {
                if (i != index)
                    offset += snprintf(output + offset, BUFFERSIZE, "Client %d is at socket %d.\n", i + 1, Client[i].sockID);
                logOperations(output);
            }
            string encodee = output;

            string encodedOutput = base64_encode(reinterpret_cast<const unsigned char *>(encodee.c_str()), encodee.length());
            int n = encodedOutput.length(); //convert string into char...
            char listofclients[n + 1];
            strcpy(listofclients, encodedOutput.c_str());

            if (controlToken(authentication) == 1)
            {
                send(clientSocket, listofclients, BUFFERSIZE, 0);
                continue;
            }
            else
            {
                char expiry[BUFFERSIZE] = "Token Expired";
                send(clientSocket, expiry, BUFFERSIZE, 0);
                close(clientSocket);
                clientSocket = -1;
                continue;
            }
        }
        if (strcmp(data, "HISTORY") == 0)
        {
            showHistory(clientSocket);
            continue;
        }
        //if the data is "SEND", server sends message to client(ID)
        if (strcmp(data, "SEND") == 0)
        {
            read = recv(clientSocket, data, BUFFERSIZE, 0); //read ID of other client
            data[read] = '\0';
            int id = atoi(data) - 1;

            read = recv(clientSocket, data, BUFFERSIZE, 0); //read message from client
            data[read] = '\0';
            cout << "\nDATA from socket " << clientSocket << "to socket " << Client[id].sockID << ":" << data << endl;

            sprintf(data, "%s, sent from client %d to client %d", data, index + 1, Client[id].index + 1);
            logOperations(data);

            if (controlToken(authentication) == 1)
            {
                send(Client[id].sockID, data, BUFFERSIZE, 0);
                continue;
            }
            else
            {
                char expiry[BUFFERSIZE] = "Token Expired";
                send(clientSocket, expiry, BUFFERSIZE, 0);
                close(clientSocket);
                clientSocket = -1;
                continue;
            }
            //send message to client(ID).
        }
    }

    return NULL;
}

void *receiveMessages(void *sockID){
    int clientSocket = *((int *)sockID);

    while (1)
    {
        char data[BUFFERSIZE];
        int read = recv(clientSocket, data, BUFFERSIZE, 0);
        if (read == 0)
        {
            cout << "Token expired, log in again." << endl;
            logOperations("Connection lost with server");
            close(clientSocket);
            exit(1);
        }
        //data[read] = '\0';
        string decodedMessage = base64_decode(data);

        cout <<  decodedMessage << endl;
    }
}

void insideMenu(){
    cout << "Choose what to do :" << endl;
    cout << "1.LIST\t 2.SEND\t 3.HISTORY 4.EXIT\n"
         << endl;
}

void controlSendToken(int anySocket, string authenticationToken){
    int n = authenticationToken.length();

    char tokenChar[n + 1];

    strcpy(tokenChar, authenticationToken.c_str());

    int bytesSent = send(anySocket, tokenChar, strlen(tokenChar), 0);
}

string recieveToken(int anySocket){
    string tokenToControl;
    int bytesRecv = read(anySocket, buffer, sizeof(buffer));
    tokenToControl = buffer;
    return tokenToControl;
}

bool controlToken(string authenticationToken){
    time_t now = time(0);
    int n = authenticationToken.length();

    char tokenChar[n + 1];

    strcpy(tokenChar, authenticationToken.c_str());
    string decodedToken = base64_decode(tokenChar);
    int n1 = decodedToken.length();

    char tokenChar2[n1 + 1];

    strcpy(tokenChar2, decodedToken.c_str());
    struct tm tm;
    strptime(tokenChar2, "%c", &tm);
    time_t t = mktime(&tm); // t is now your desired time_t

    double diff = difftime(t, now);
    if (diff < 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

const char *getCurrentTime(){ //returns current time and date.{
    time_t rawtime;
    struct tm *info;
    time(&rawtime);
    info = localtime(&rawtime);
    return asctime(info);
}

string getCurrentTimeForDB() { // Function to get the current time and return it as a string
    time_t now = time(0);
    string dt = ctime(&now);
    return dt;
}

string determineExpiryDate() { // determines expiry date for token
    time_t now = time(0);

    size_t Minutes = 255;

    time_t expiryDate = now + (0.5 * Minutes);

    struct tm tNewTime;
    memset(&tNewTime, '\0', sizeof(struct tm));
    localtime_r(&expiryDate, &tNewTime);

    string expiryDateChar = asctime(&tNewTime);

    return expiryDateChar;
}

string generateToken(){
    string expiryDate = determineExpiryDate();
    string encodedExpiryDate = base64_encode(reinterpret_cast<const unsigned char *>(expiryDate.c_str()), expiryDate.length());
    return encodedExpiryDate;
}

#endif