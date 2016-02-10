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

#define BCAST_ADDR "192.168.10.255"	// ou #define BCAST_ADDR (192<<24+168<<16+3<<8+255) puis htons(BCAST_ADDR)
#define BCAST_PORT 1234


typedef enum msg_type
{
    MT_INVAL = 0,
    MT_HELLO = 1,
    MT_MSG   = 2,
    MT_NICK  = 3,
    MT_COLOR = 4,
    MT_MAX,
} msg_type_t;

#define BUF_SIZE 1024
typedef struct msg
{
    msg_type_t  type;
    uint16_t    len;
    char        buf[BUF_SIZE];
} msg_t;
#define MSG_SIZE sizeof(msg_t)




/***** GLOBAL VARIABLES *****/

int bcast_sock = -1;
struct sockaddr bcast_addr;




/***** PROTOTYPE DE FONCTIONS *****/

int init_bcast(struct sockaddr *bcast_addr);
msg_t *get_buf(msg_type_t type);
void free_buf(msg_t *buf);




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
	
	
	return sockfd;
}

msg_t *get_buf(msg_type_t type)
{
    msg_t *msg = NULL;

    char* buffer = malloc((BUF_SIZE + 1) * sizeof(char));
    int byteRead;
    int i = 0;
	while((byteRead = recv(bcast_sock, buffer, BUF_SIZE, 0)) > 0)
	{
		if(byteRead <= 0)
		    break;
		else {
		    msg->buf[i] = *buffer;
		    //printf("%s", buffer);
		}
		i++;
	}
	msg->buf[i+1] = '\0';
	
	msg->type = type;
	msg->len = i+1;

    return msg;
}

void free_buf(msg_t *buf)
{
    free(buf);
}
