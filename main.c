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

//#define BCAST_ADDR "192.168.10.255"	// ou #define BCAST_ADDR (192<<24+168<<16+3<<8+255) puis htons(BCAST_ADDR)
//#define BCAST_PORT 1234

#define BCAST_ADDR "192.168.1.255"	// ou #define BCAST_ADDR (192<<24+168<<16+3<<8+255) puis htons(BCAST_ADDR)
#define BCAST_PORT 5000


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
struct sockaddr_in bcast_addr_in;




/***** PROTOTYPE DE FONCTIONS *****/

int init_bcast(struct sockaddr *bcast_addr);
msg_t *get_buf(msg_type_t type);
void free_buf(msg_t *buf);
user_t *add_user(struct sockaddr_in *sa);
void get_node_info(user_t *user, struct sockaddr_in *si);
void del_user(user_t *user);
user_t *lookup_user(struct sockaddr_in *sa);
void show_users();
void *receive_thread(void *arg);
void process_received_msg(user_t *user, msg_t *msg);
void send_msg(msg_t *data, size_t data_len);
void enter_loop(void);




/***** MAIN *****/

int main (int argc, char **argv)
{
	printf("Bienvenue, vous pouvez discutez avec les personnes connectées sur le réseau !\n");
	
	pthread_t receive_th;
	int rc;

	bcast_sock = init_bcast(&bcast_addr);

    rc = pthread_create(&receive_th, NULL, receive_thread, NULL);
    if (rc < 0)
    	printf("Cannot create receive thread\n");

    enter_loop();

	
	return 0;
}




/***** FONCTIONS *****/

int init_bcast(struct sockaddr *bcast_addr)
{
	int sockfd;
	struct sockaddr_in broadcastAddr;
	int broadcastPermission;

	if ((sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        perror("socket() failed");

    broadcastPermission = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (void *) &broadcastPermission, sizeof(broadcastPermission)) < 0)
        perror("setsockopt() failed");

    memset(&broadcastAddr, 0, sizeof(broadcastAddr));
    broadcastAddr.sin_family = AF_INET;
    broadcastAddr.sin_addr.s_addr = inet_addr(BCAST_ADDR);
    broadcastAddr.sin_port = htons(BCAST_PORT);

    if (bind(sockfd, (struct sockaddr *) &broadcastAddr, sizeof(broadcastAddr)) < 0)
        perror("bind() failed");

    bcast_addr = (struct sockaddr *) &broadcastAddr;
    bcast_addr_in = broadcastAddr;
	return sockfd;
}

msg_t *get_buf(msg_type_t type)
{
    msg_t *msg = malloc(MSG_SIZE);
	msg->type = type;

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

void *receive_thread(void *arg)
{
	while (1)
    {
        struct sockaddr_in sender_addr;
        unsigned int addrlen = sizeof(sender_addr);
        user_t *sender = NULL;
        void *data = malloc(MSG_SIZE);
        msg_t *msg = get_buf(MT_INVAL);

		if((recvfrom(bcast_sock, data, MSG_SIZE, 0, (struct sockaddr *) &sender_addr, &addrlen)) != MSG_SIZE)
			printf("Erreur de reception %d\n", errno);
		else
		{
			sender = lookup_user(&sender_addr);
			if (sender == NULL)
				sender = add_user(&sender_addr);

			process_received_msg(sender, (msg_t*) data);
		}
    }
    return NULL;
}

void process_received_msg(user_t *user, msg_t *msg)
{
    switch(msg->type)
    {
        case MT_HELLO:
            {
                printf("%d\n", msg->type);
            }
            break;

        case MT_NICK:
            {
                printf("%d\n", msg->type);
            }
            break;

        case MT_MSG:
            {
                printf("%s : %d : %s", inet_ntoa(user->sa.sin_addr), msg->type, msg->buf);
            }
            break;

        case MT_COLOR:
            {
                printf("%d\n", msg->type);
            }
            break;

        default:
            perror("Invalid message type");
            break;
    }
}

void send_msg(msg_t *data, size_t data_len)
{
    if(sendto(bcast_sock, data, data_len, 0, (struct sockaddr *) &bcast_addr_in, sizeof(bcast_addr_in)) != MSG_SIZE)
    	printf("Erreur %d lors de l'envoie du message\n", errno);
}

void enter_loop(void)
{
    while (1)
    {
        char str[BUF_SIZE];

        fgets(str, BUF_SIZE, stdin);

        msg_t * msg = get_buf(MT_MSG);
		msg->len = BUF_SIZE;
		strncpy(msg->buf, str, BUF_SIZE);
        send_msg(msg, MSG_SIZE);
        free_buf(msg);
    }
}