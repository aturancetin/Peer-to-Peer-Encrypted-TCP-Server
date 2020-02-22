//Serve Side
#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#include <iostream>
#include <pthread.h>

#include "functions.h"


using namespace std;


int main(int argc, char const *argv[]) 
{ 
	int serverGateSocket, mainServerSocket;   // Defines sockets for server gate and main server
	string pass; // buffer to recieve username of the client
	
	serverGateSocket = createSocket(); // Creating socket file descriptor for the server gate
    mainServerSocket = createSocket(); // Creating socket file descriptor for the main server
	
    struct sockaddr_in serverGateAddress = defineAddress(SERVERGATEPORT); //Defines address information for server gate address
    struct sockaddr_in mainServerAddress = defineAddress(MAINSERVERPORT); //Defines address information for main server address
	
	bindSocket(serverGateSocket,serverGateAddress); // Bind server gate socket
	bindSocket(mainServerSocket,mainServerAddress); // Bind main server socket

	listenForConnections(serverGateSocket); // Listen for connections from server gate socket
	listenForConnections(mainServerSocket); // Listen for connections from main server socket


	while (1) // Accept connection to server gate and after a successfull log in recieve client's username
	{
		if((Client[clientCount].sockID = acceptConnection(serverGateSocket,&Client[clientCount], clientCount)) != -1){
			Client[clientCount].username = recvUsername(Client[clientCount].sockID,pass); // Recieve logged in client's username
			if(Client[clientCount].username != ""){
			sendToken(Client[clientCount].sockID);
			}
		}
			// If username of the client exist, accept connection to main server
		
			Client[clientCount].sockID = acceptConnection(mainServerSocket, &Client[clientCount], clientCount); //if user is valid, connects user to the communication port
        	Client[clientCount].index = clientCount;
			Client[clientCount].authToken = recieveToken(Client[clientCount].sockID);

    		//creating thread that handle communication for each client.
        	pthread_create(&serverThread[clientCount], NULL, sendAndReceive, (void *)&Client[clientCount]);

			clientCount++;

			continue;
			
	}
	return 0; 
} 
