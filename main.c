#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <netdb.h>

#define BCAST_ADDR "192.168.10.255"
#define BCAST_PORT 1234

/***** GLOBAL VARIABLES *****/
int bcast_sock = -1;
struct sockaddr bcast_addr;

/***** PROTOTYPE DE FONCTIONS *****/
int init_bcast(struct sockaddr *bcast_addr);

/***** MAIN *****/
int main (int argc, char **argv)
{
	printf("Hello world !\n");
	
	bcast_sock = init_bcast(&bcast_addr);
	
	return 0;
}

/***** FONCTIONS *****/
int init_bcast(struct sockaddr *bcast_addr)
{
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	
	int sock = -1;
	sock = bind(sockfd, bcast_addr, sizeof(struct sockaddr));
	int broadcastPermission = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (void *) &broadcastPermission, sizeof(broadcastPermission));
	
	if (sock == -1)
		printf("Erreur init_bcast\n");
	
	
	return sock;
}
