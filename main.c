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


#define NB_USER 100
#define NICK_DEFAULT "Guest"
#define COLOR_DEFAULT (colors[0].name)
#define NICK_LEN 256
#define NODE_INFO_LEN 256
typedef struct user
{
    struct sockaddr_in      sa;
    char                    nick[NICK_LEN];
    char                    node_info[NODE_INFO_LEN];
    const char             *color;
} user_t;

user_t users[NB_USER];
int user_online = 0;



/***** GLOBAL VARIABLES *****/

int bcast_sock = -1;
struct sockaddr bcast_addr;




/***** PROTOTYPE DE FONCTIONS *****/

int init_bcast(struct sockaddr *bcast_addr);
msg_t *get_buf(msg_type_t type);
void free_buf(msg_t *buf);
user_t *add_user(struct sockaddr_in *sa);
void get_node_info(user_t *user, struct sockaddr_in *si);
void del_user(user_t *user);
user_t *lookup_user(struct sockaddr_in *sa);
void show_users();




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

user_t *add_user(struct sockaddr_in *sa)
{
	user_t *user = NULL;
	
	user = malloc(sizeof(user_t));
	if (user != NULL)
	{
		user->sa = *sa;
		strncpy(user->nick, NICK_DEFAULT, NICK_LEN);
		get_node_info(user, sa);
		//user.color = COLOR_DEFAULT;
	
		users[user_online] = *user;
		user_online++;
	}
	else
		printf("ERREUR : Allocation utilisateur échouée\n");
	
	return user;
}

void get_node_info(user_t *user, struct sockaddr_in *sa)
{
	int port = sa->sin_port;
	char *ip = inet_ntoa(sa->sin_addr);
	sprintf(user->node_info, "%d", port);
	strcat(user->node_info, ":");
	strcat(user->node_info, ip);
}

void del_user(user_t *user)
{
	int i;
	int supprimer = 0;
	for(i=0 ; i < user_online-1 ; i++)
	{
		if (supprimer == 0 && memcmp(&(&users[i])->sa, &user->sa, sizeof(struct sockaddr_in)) == 0)
			supprimer = 1;
		if (supprimer == 1)		
			users[i] = users[i+1];
	}
	user_t empty;
	users[user_online-1] = empty;
	user_online--;
}

user_t *lookup_user(struct sockaddr_in *sa)
{
	user_t *user = NULL;
	int i;
    for(i=0 ; i < user_online-1 ; i++)
	{
		if (memcmp(&(&users[i])->sa, &sa, sizeof(struct sockaddr_in)) == 0)
		{
			user = &(user[i]);
			return user;
		}
	}
    return user;
}

void show_users()
{
	int i;
    for(i=0 ; i < user_online-1 ; i++)
	{
		printf("User %s\n", users[i].nick);
		printf("\tUsing color %s\n", users[i].color);
		printf("\tConnected with %s\n", users[i].node_info);
	}
}
