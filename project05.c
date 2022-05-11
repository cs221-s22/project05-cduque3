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

int new_socket(int socktype, int protocol, char* service, bool udp) {

	int socketfd;
	
	//struct that will specify requirements to filter received socket structures in getaddrinfo() below
	struct addrinfo hints;
    memset(&hints, 0, sizeof(hints)); //fills block of memory of hints to 0
    hints.ai_family = PF_INET;    // Allow IPv4 or IPv6
    hints.ai_socktype = socktype; // SOCK_DGRAM or SOCK_STREAM
    hints.ai_flags = AI_PASSIVE;    // Any IP address (DHCP)
    hints.ai_protocol = protocol;   // IPPROTO_UDP or IPPROTO_TCP

    //getaddrinfo() converts network host information to the IP address
	//produces list of structs (result) that contain an Internet address each that can be specified in call to bind
	struct addrinfo *result;
    int s = getaddrinfo(NULL, service, &hints, &result); //result now contains list of those structs
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

        if (udp == true) { //setup SO_BROADCAST for UDP
        	int enable_broadcast = 1;
			setsockopt(socketfd, SOL_SOCKET, SO_BROADCAST, &enable_broadcast, sizeof(int));
			if (setsockopt(socketfd, SOL_SOCKET, SO_BROADCAST, &enable_broadcast, sizeof(int)) == -1) {
				perror("setsockopt broadcast");
				exit(-1);
			}
		}
		else { //setup non_blocking and listening for TCP
			int enable = 1; 
			ioctl(socketfd, FIONBIO, (char*) &enable);

			//listen(socketfd, 0);
			if(listen(socketfd, 0) != 0){
							perror("listen");
							exit(-1);
			}
		}    
 
		//bind function assigns address to unbound socket
        if (bind(socketfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
		}

    	freeaddrinfo(result);  // No longer needed

    	if (rp == NULL) {  // No address succeeded
        	fprintf(stderr, "Could not bind\n");
        	exit(EXIT_FAILURE);
    	}
    }	

    return socketfd;
} 

void send_presence(int socket, int port, char *message) {
	char *buf = message;
	struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in)); //fills block of memory of addr to 0
    addr.sin_family = PF_INET; //sets to IPv4
    addr.sin_port = htons (port); //htons = host to network short ,, switch host byte order (8221) to network byte order
    inet_pton(PF_INET, "10.10.13.255", &addr.sin_addr);	

	int sent = sendto(socket, buf, strlen(buf), 0, (struct sockaddr*) &addr, sizeof(struct sockaddr_in));
	printf("%s\n", buf);
}

struct user receive_presence(int socket) {

	struct sockaddr_storage peer_addr; 
	socklen_t peer_addr_len;
	ssize_t nread; //ssize_t used for count of bytes / error indication
	char buf[BUF_SIZE];
	peer_addr_len = sizeof(peer_addr);

    //sees what's on socket, peer_addr will hold address of who sent it and buf will hold its message
    nread = recvfrom(socket, buf, BUF_SIZE, 0, (struct sockaddr *) &peer_addr, &peer_addr_len);

	//getnameinfo() retrieves hostnames for corresponging IP addresses
	//given peer_addr, host will now hold the hostname of that address
	char host[NI_MAXHOST], service[NI_MAXSERV];
	int s = getnameinfo((struct sockaddr *) &peer_addr,
    		peer_addr_len, host, NI_MAXHOST,
     	      	service, NI_MAXSERV, NI_NUMERICSERV);
                
    if (s == 0) {				
    	printf("%s %s\n", buf, host);
    }

	char online[BUF_SIZE];
    char user[BUF_SIZE];
    char port[BUF_SIZE];

    sscanf(buf, "%s %s %s", online, user, port);

    struct user new_user = create_user(user, host, port); 

    return new_user;

	//sendto function sends message on socket
    if (sendto(socket, buf, nread, 0,(struct sockaddr *) &peer_addr, peer_addr_len) != nread) {
    	fprintf(stderr, "Error sending response\n");
    }

    //memset(buf, 0, BUF_SIZE);
    memset(host, 0, BUF_SIZE);
    memset(user, 0, BUF_SIZE);
    memset(port, 0, BUF_SIZE);
}

int accept_connection(int socket) {
	int new_socket = accept(socket, NULL, NULL);
	if (new_socket != 0) {
		perror("accept");
	return new_socket;
	}
}

void read_message(int socket, struct user *u) {
	char buf[BUF_SIZE];
	int rc = recv(socket, buf, BUF_SIZE, 0);
	if (rc == -1)
		perror("recv for chat");
	else if (rc == 0)
		printf("closed");
	else {
		struct sockaddr_in peer;
		socklen_t peer_len = sizeof(peer);

		if (getpeername(socket, (struct sockaddr*) &peer, &peer_len) != 0) {
			perror("getpeername");
		}

		char host[NI_MAXHOST];
		char service[NI_MAXSERV];

		int rc = getnameinfo((struct sockaddr *) &peer, peer_len,
			host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV);

		if (rc == 0) {
    		printf("%s %s\n", buf, host);
    	}
	}
}

void send_message(struct user *u, char *message) {
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo *result;
    int s = getaddrinfo(u->host, u->port, &hints, &result); //result now contains list of those structs
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

    int new_socket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

    if (connect(new_socket, result->ai_addr, result->ai_addrlen) != 0) {
    	printf("failed to connect to %s %s\n", u->host, u->port);
    	perror("connect");
    }

    int len = strlen(message) + 1;

	int sent = send(new_socket, message, len, 0);
    
    if (send(new_socket, message, len, 0) != 0)
    	perror("send");
    	
}
	

int main(int argc, char *argv[])
{
    char* class_port = "8221";
    char* my_port = "8326"; //second port: "8327"
    
    int udp_socket = new_socket(SOCK_DGRAM, IPPROTO_UDP, class_port, true);
    send_presence(udp_socket, 8221, "online crduque 8326");
    
    int tcp_socket = new_socket(SOCK_STREAM, IPPROTO_TCP, my_port, false);

	struct pollfd fds[64];
	int nfds = 0;

	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;
	nfds++;

	fds[1].fd = udp_socket;
	fds[1].events = POLLIN;
	nfds++;

	fds[2].fd = tcp_socket;
	fds[2].events = POLLIN;
	nfds++;

	int timeout = 100;
	int n = 0;

	struct user user_data[61];
	int user_socket[61];
	int user_count = 0;

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
						//printf("typing\n");		
						int letter = 0;
						int put;

						while((put = getchar()) != EOF && put != '\n') {
							buf[letter] = put;
							count++;
						}

					
						char user[BUF_SIZE];
						sscanf(buf, "%s", user);

					/*	for(int i = 0; i < user_count; i++) {
							if(user == user_data[user_count].name) {
								send_message(user_)
							}
						}*/
						/*for(i = 0; i < user_count; i++) {
							if()
						}*/
						//printf("typing\n");
						//printf("%s", buf);
						//send_message(tcp_socket, 8221, buf);
						memset(buf, 0, BUF_SIZE);					
						
					}

					//accumulates users when they go online
					if (fds[i].fd == udp_socket) {
						//printf("udp\n");
						
						//create struct with user data
						user_data[user_count] = receive_presence(udp_socket);
						user_count++;
						/*printf("%s\n %s\n %s\n ", user_data[user_count].name, 
							user_data[user_count].port, user_data[user_count].host);
						
					/*	//create TCP socket for user 
						user_socket[user_count] = new_socket(SOCK_STREAM, IPPROTO_TCP, user_data[user_count].port, false);

						//create new file descriptor for POLL
						fds[3 + user_count].fd = user_socket[user_count];
						fds[3 + user_count].events = POLLIN;
						user_count++;
						nfds++;
					*/
											
						//do UDP server stuff
						//recvfrom(), getnameinfo()
					}
					if (fds[i].fd == tcp_socket) {
						//printf("tcp\n");
						user_socket[user_count] = accept_connection(tcp_socket); 
						fds[3 + user_count].fd = user_socket[user_count];
						fds[3 + user_count].events = POLLIN;
						user_count++;
						nfds++;					

						//accept() -> new socket fd
					}
					if(fds[i].fd == user_socket[i]) {
						//printf("user\n");
						//read_message(user_socket[i]);
						
					}
				}
			}
		}
	}	
}

