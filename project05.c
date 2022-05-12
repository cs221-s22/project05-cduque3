#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <fcntl.h>

#define BUF_SIZE 1000

struct user {
	char status[BUF_SIZE];
	char name[BUF_SIZE];
	char port[BUF_SIZE];
	char host[NI_MAXHOST];
};

struct user create_user(char *name, char *host, char* port) {
	struct user new_user;
	
	strcpy(new_user.status, "online");
	strcpy(new_user.name, name);
	strcpy(new_user.port, port);
	strcpy(new_user.host, host);
	
	return new_user;
}	

//creates and returns new socket based on input from user regarding TCP or UDP
int new_socket(int socktype, int protocol, char* service, bool udp) {

	int socketfd;
	
	//struct that will specify requirements to filter received socket structures in getaddrinfo() below
	struct addrinfo hints;
    memset(&hints, 0, sizeof(hints)); //fills block of memory of hints to 0
    hints.ai_family = PF_INET;    // Allow IPv4 or IPv6
    hints.ai_socktype = socktype; // SOCK_DGRAM or SOCK_STREAM
    hints.ai_flags = AI_PASSIVE;    // Any IP address (DHCP)
    hints.ai_protocol = protocol;   // IPPROTO_UDP or IPPROTO_TCP

    //converts network host information to the IP address
	struct addrinfo *result;
    int s = getaddrinfo(NULL, service, &hints, &result); 
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

	//tries each address stored in result until bind is successful
	struct addrinfo *rp;
    for (rp = result; rp != NULL; rp = rp->ai_next) {

        socketfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (socketfd == -1)
            continue; 

		//set SO_REUSEADDR for both UDP and TCP
		int enable_reuseaddr = 1;
        setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &enable_reuseaddr, sizeof(int));
		if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &enable_reuseaddr, sizeof(int)) != 0) {
			perror("setsockopt reuseaddr");
			exit(-1); 
		} 
	 	//setup SO_BROADCAST for UDP
        if (udp == true) {
        	int enable_broadcast = 1;
			setsockopt(socketfd, SOL_SOCKET, SO_BROADCAST, &enable_broadcast, sizeof(int));
			if (setsockopt(socketfd, SOL_SOCKET, SO_BROADCAST, &enable_broadcast, sizeof(int)) == -1) {
				perror("setsockopt broadcast");
				exit(-1);
			}
		}

		//try next address if bind unsuccessful
        if (bind(socketfd, rp->ai_addr, rp->ai_addrlen) != 0) {
			continue;
		}

		//setup non_blocking and listening for TCP if bind successful
		if (udp == false) { 
			int enable = 1; 
			ioctl(socketfd, FIONBIO, (char*) &enable);
		
			if(listen(socketfd, 0) != 0){
				perror("listen");
				exit(-1);
			}
		}   
		
		break;
    }	

    freeaddrinfo(result);  // not needed anymore
    
    if (rp == NULL) {  // no address succeeded
    	fprintf(stderr, "Could not bind\n");
        exit(EXIT_FAILURE);
    }

    return socketfd;
} 

//broadcast name and port number to network using UDP
void send_presence(int socket, int port, char *message) {
	char *buf = message; //use manual input: "online [username] [port number]"

	//specify network to send presence to
	struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in)); 
    addr.sin_family = PF_INET; 
    addr.sin_port = htons (port);  
    inet_pton(PF_INET, "10.10.13.255", &addr.sin_addr);	

	//now send presence message over network
	int len = strlen(buf) + 1;
	int sent = sendto(socket, buf, len, 0, (struct sockaddr*) &addr, sizeof(struct sockaddr_in));

}

//see broadcasts from other users, then store their info into a user struct
struct user receive_presence(int socket) {

	struct sockaddr_storage peer_addr; 
	socklen_t peer_addr_len;
	ssize_t nread; 
	char buf[BUF_SIZE];
	peer_addr_len = sizeof(peer_addr);

    //peer_addr to hold address of received socket 
    //buf to hold its message
    nread = recvfrom(socket, buf, BUF_SIZE, 0, (struct sockaddr *) &peer_addr, &peer_addr_len);

	//now with peer_addr, host will now hold the hostname of that address
	char host[NI_MAXHOST], service[NI_MAXSERV];
	int s = getnameinfo((struct sockaddr *) &peer_addr,
    		peer_addr_len, host, NI_MAXHOST,
     	      	service, NI_MAXSERV, NI_NUMERICSERV);

    //print presence message and the host       
    if (s == 0) {				
    	printf("%s %s\n", buf, host);
    }

	//variables to hold elements in the received broadcast
	char online[BUF_SIZE];
    char user[BUF_SIZE];
    char port[BUF_SIZE];

	//parse the broadcast to receive the username and port number
    sscanf(buf, "%s %s %s", online, user, port);

	//store variables and return new user struct 
    struct user new_user = create_user(user, host, port); 
    return new_user;
}

//create new socket for other user when TCP listener receives their message
int accept_connection(int socket) {
	int new_socket = accept(socket, NULL, NULL);
	if (new_socket != 0) {
		perror("accept");
	return new_socket;
	}
}

//read message from new socket that came from TCP listener
void read_message(int socket, struct user *u) {
	//to hold the message
	char buf[BUF_SIZE];

	//store message received from socket in buf
	int rc = recv(socket, buf, BUF_SIZE, 0);

	//case for error and closed socket
	if (rc == -1)
		perror("recv for chat");
	else if (rc == 0) 
		printf("closed"); 

	//print message
	else {		
    	printf("%s: %s\n", u->name, buf);
    }	

}

//send message to recipient via TCP
void send_message(struct user *u, char *message) {

	//specify TCP socket
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;

	//get user's host and port
	struct addrinfo *result;
    int s = getaddrinfo(u->host, u->port, &hints, &result); //result now contains list of those structs
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

	//create new socket from user's host and port
    int new_socket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

	//connect to user's socket
    if (connect(new_socket, result->ai_addr, result->ai_addrlen) != 0) {
    	printf("failed to connect to %s %s\n", u->host, u->port);
    	perror("connect");
    }

	//send message to newly created socket
    int len = strlen(message) + 1;
	int sent = send(new_socket, message, len, 0);

    //error handling
    if (send(new_socket, message, len, 0) != 0)
    	perror("send");
    	
}
	

int main(int argc, char *argv[])
{
	//initialize ports and sockets
    char* class_port = "8221";
    char* my_port = "8326"; //second port: "8327"
    
    int udp_socket = new_socket(SOCK_DGRAM, IPPROTO_UDP, class_port, true);
    int tcp_socket = new_socket(SOCK_STREAM, IPPROTO_TCP, my_port, false);

    send_presence(udp_socket, 8221, "online crduque 8326");

	//create all poll elements
	struct pollfd fds[63];
	int nfds = 0;
	int timeout = 100;

	//for reading user input
	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;
	nfds++;

	//for udp_socket events
	fds[1].fd = udp_socket;
	fds[1].events = POLLIN;
	nfds++;

	//for tcp_socket events
	fds[2].fd = tcp_socket;
	fds[2].events = POLLIN;
	nfds++;


	int n = 0;

	struct user user_data[61]; //structs that will hold each user's info
	int user_socket[61]; //sockets for all accumulated users
	int user_count = 0; //count of all accumulated users 

	char buf[BUF_SIZE];
	
	while (1) {
		int count = poll(fds, nfds, timeout);
		//printf("count: %d\n", count);
		//printf("nfds: %d\n", nfds);
		if (count == 0) {
		//printf("here");
			if(n == 100) {
				send_presence(udp_socket, 8221, "online crduque 8326");
				n = 0;
			}
			n++;
		}
		else if (count > 0) {
			for (int i = 0; i < nfds; i++) {
				if (fds[i].revents & POLLIN) {					
					if (fds[i].fd == STDIN_FILENO) {		

						//get input from user and store in buf
						int letter = 0;
						int put;
						while((put = getchar()) != EOF && put != '\n') {
							buf[letter] = put;
							letter++;
						}

						//store the username given in the input
						char user[BUF_SIZE];
						sscanf(buf, "%s\n", user ); 

						//find the user specified in input and send message to them
						//nothing sent if cant find user
						for(int i = 0; i < user_count; i++) {
							//printf("user:%s user: %s\n", user, user_data[i].name);
							if(strcmp(user, user_data[i].name) == 0) {
								send_message(&user_data[i], buf);
							}
						}							
					}

					//accumulates users when they go online
					if (fds[i].fd == udp_socket) {

						//create struct with user data from their broadcast
						struct user new_user = receive_presence(udp_socket);
						int counter = user_count + 1;
						bool new = true;

						//see if user who sent broadcast already exists in our created structs
						for (int j = 0; j < counter; j++) {
							if (strcmp(new_user.name, user_data[j].name) == 0
							  || strcmp(new_user.name, "crduque") == 0 ) {
								new = false;
								if (strcmp(new_user.status, user_data[j].status) != 0) {
									
								}
							}
						}

						//if user does not exist, create new struct
						//do nothing if they're already in a struct
						if (new == true) {
							user_data[user_count] = new_user;						 
							user_count++;
						}
					}						

					//create new socket to communicate with other users if they send message
					//to our TCP listener
					if (fds[i].fd == tcp_socket) {
						printf("tcp\n");
						user_socket[3 - nfds] = accept_connection(tcp_socket); 
						fds[nfds].fd = user_socket[3 - nfds];
						fds[nfds].events = POLLIN;
						nfds++;					

					}

					//read messages from existing sockets we've created from users
					if(fds[i].fd == user_socket[i + 1 - nfds]) {
						printf("user\n");
						read_message(user_socket[i + 1 - nfds], &user_data[i + 1 - nfds]);
						
					}
				}
			}
		}
	}	
}

