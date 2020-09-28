# Peer-to-Peer-Encrypted-TCP-Server

The aim of this project is to set up a TCP based server for multiple clients that can send and receive messages between each other.

## How to compile ?

```bash
g++ server.cpp -o server -lpthread -lsqlite3
g++ client.cpp -o client -lpthread -lsqlite3
```
## How to run ?

```bash
./server
./client
```

## How to use ?

In order to use the server, you must register with a username and a password.<br/>
Once registration is complete, your username and your hashed password is saved to the server.<br/>
After you register, client side will be closed automatically for you to login to server. Before you log in, close the server and rerun the server.(This will update the users database.)<br/>
Log in to the server.

### LIST FUNCTION

In order to list the connected online clients give this command ; 

```bash
LIST
```


### SEND FUNCTION

In order to send message to another client give this command ;

```bash
SEND <CLIENT NUMBER> <YOUR MESSAGE>
```

Here <CLIENT NUMBER> is the number which you receive after you give LIST command.

### HISTORY FUNCTION

In order to see history of messages, give this command ;

```bash
HISTORY
```

### EXIT FUNCTİON

In order to exit from the server give this command ;

```bash
EXIT
```

# 

For any questions, mail me ; aturancetinn@gmail.com
