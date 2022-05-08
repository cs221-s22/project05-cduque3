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

int new_socket(int socktype, int protocol, char *service, bool broadcast) {

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

		int enable_reuseaddr = 1;
        setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &enable_reuseaddr, sizeof(int));
		if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &enable_reuseaddr, sizeof(int)) != 0) {
			perror("setsockopt reuseaddr");
			exit(-1); 
		} 

        if (broadcast == true) {
        	int enable_broadcast = 1;
			setsockopt(socketfd, SOL_SOCKET, SO_BROADCAST, &enable_broadcast, sizeof(int));
			if (setsockopt(socketfd, SOL_SOCKET, SO_BROADCAST, &enable_broadcast, sizeof(int)) == -1) {
						perror("setsockopt broadcast");
						break; 
			}
		}
 
		//bind function assigns address to unbound socket
        if (bind(socketfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;  // Success
		}
		else {
			perror("bind");
		}
    }

    freeaddrinfo(result);  // No longer needed

    if (rp == NULL) {  // No address succeeded
        fprintf(stderr, "Could not bind\n");
        exit(EXIT_FAILURE);
    }	

    return socketfd;
} 

void send_message(int socket, int port, char* message) {
	struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in)); //fills block of memory of addr to 0
    addr.sin_family = PF_INET; //sets to IPv4
    addr.sin_port = htons (port); //htons = host to network short ,, switch host byte order (8221) to network byte order
    inet_pton(PF_INET, "10.10.13.255", &addr.sin_addr);	

	int sent = sendto(socket, message, strlen(message), 0, (struct sockaddr*) &addr, sizeof(struct sockaddr_in));							
}

void receive_message(int socket) {

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
        				
    else {
    	fprintf(stderr, "getnameinfo: %s\n", gai_strerror(s)); 
    }

	//sendto function sends message on socket
    if (sendto(socket, buf, nread, 0,(struct sockaddr *) &peer_addr, peer_addr_len) != nread) {
    	fprintf(stderr, "Error sending response\n");
    }

    memset(buf, 0, BUF_SIZE);
}

int main(int argc, char *argv[])
{
    char* class_port = "8221";
    char* my_port = "8326"; //"8327"
    int udp_socket = new_socket(SOCK_DGRAM, IPPROTO_UDP, class_port, true);
    int tcp_socket = new_socket(SOCK_STREAM, IPPROTO_TCP, my_port, false);

	struct pollfd fds[64];
	int nfds = 0;

	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;
	nfds++;

	fds[1].fd = udp_socket;
	fds[1].events = POLLIN;
	nfds++;

	int timeout = 100;
	int n = 0;
	char buf[BUF_SIZE];
	while (1) {
		int count = poll(fds, nfds, timeout);
		//printf("count: %d\n", count);
		//printf("nfds: %d\n", nfds);
		if (count == 0) {
		//printf("here");
			if(n == 100) {
				send_message(udp_socket, 8221, "online crduque 8326");
				n = 0;
			}
			n++;
		}
		else if (count > 0) {
			for (int i = 0; i < count; i++) {
			
				if (fds[i].revents & POLLIN) {
				
					if (fds[i].fd == STDIN_FILENO) {			
						int count = 0;
						int put;

						while((put = getchar()) != EOF && put != '\n') {
							buf[count] = put;
							count++;
						}
						//printf("%s\n", buf);
						send_message(udp_socket, 8221, buf);
						memset(buf, 0, BUF_SIZE);					
						
					}
					if (fds[i].fd == udp_socket) {
						receive_message(udp_socket);	
						n++;
						//printf("%i", n);
						//do UDP server stuff
						//recvfrom(), getnameinfo()
					}
			//		if (fds[i].fd == tcp_socket) {
					//do TCP server stuff
					//accept() -> new socket fd
			//		}
				}
			}
		}
	}	
}

