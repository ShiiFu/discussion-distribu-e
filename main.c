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

#include "sys/queue.h"

//#define BCAST_ADDR "192.168.10.255"	// ou #define BCAST_ADDR (192<<24+168<<16+3<<8+255) puis htons(BCAST_ADDR)
//#define BCAST_PORT 1234

#define BCAST_ADDR "127.0.0.1"	// ou #define BCAST_ADDR (192<<24+168<<16+3<<8+255) puis htons(BCAST_ADDR)
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


#define NB_USER 5
#define NICK_DEFAULT "Guest"
#define COLOR_DEFAULT 1
#define NICK_LEN 256
#define NODE_INFO_LEN 256
typedef struct user
{
	TAILQ_ENTRY(user)       lh;
    struct sockaddr_in      sa;
    char                    nick[NICK_LEN];
    char                    node_info[NODE_INFO_LEN];
    int                     color;
    int                     last_msg;
} user_t;

TAILQ_HEAD(mylist, user) users_list;



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
void *hello_thread(void *args);
void free_user();




/***** MAIN *****/

int main (int argc, char **argv)
{
    printf("\x1B[0mBienvenue, vous pouvez discutez avec les personnes connectées sur le réseau !\n");
	
	pthread_t receive_th;
	pthread_t hello_th;
	int rc;

	TAILQ_INIT(&users_list);

	bcast_sock = init_bcast(&bcast_addr);

    rc = pthread_create(&receive_th, NULL, receive_thread, NULL);
    if (rc < 0)
    	printf("Cannot create receive thread\n");

    rc = pthread_create(&hello_th, NULL, hello_thread, NULL);
    if (rc < 0)
    	printf("Cannot create hello thread\n");

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
		user->color = COLOR_DEFAULT;
	
		TAILQ_INSERT_TAIL(&users_list, user, lh);
	}
	else
		printf("ERREUR : Allocation utilisateur échouée\n");
	
	return user;
}

void get_node_info(user_t *user, struct sockaddr_in *sa)
{
	int port = sa->sin_port;
	char *ip = inet_ntoa(sa->sin_addr);
	sprintf(user->node_info, "%s:%d", ip, port);
}

void del_user(user_t *user)
{
    printf("%s disconnected\n", user->nick);
	TAILQ_REMOVE(&users_list, user, lh);
}

user_t *lookup_user(struct sockaddr_in *sa)
{
    user_t *user = NULL;

    TAILQ_FOREACH(user, &users_list, lh)
    {
        if (memcmp(&(user->sa), sa, sizeof(struct sockaddr_in)) == 0)
        	return user;
    }
    return NULL;
}

void show_users()
{
	user_t *user = NULL;

    TAILQ_FOREACH(user, &users_list, lh)
    {
        printf("User %s\n", user->nick);
		printf("\tUsing color %d\n", user->color);
		printf("\tConnected with %s\n", user->node_info);
        printf("\tLast message %d seconds ago\n", (int)time(NULL)-user->last_msg);
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
        free(data);
        free(msg);
    }
    return NULL;
}

void process_received_msg(user_t *user, msg_t *msg)
{
    user_t *userq = NULL;
    TAILQ_FOREACH(userq, &users_list, lh)
    {
        if (memcmp(userq, user, sizeof(user_t)) == 0)
            user->last_msg = (int)time(NULL);
    }
    switch(msg->type)
    {
        case MT_HELLO:
            {
                // Nothing more than default
            }
            break;

        case MT_NICK:
            {
                TAILQ_FOREACH(userq, &users_list, lh)
                {
                    if (memcmp(userq, user, sizeof(user_t)) == 0)
                        strncpy(user->nick, msg->buf, NICK_LEN);
                }
            }
            break;

        case MT_MSG:
            {
                printf("\x1B[%dm%s : %s\x1B[0m\n", user->color, user->nick, msg->buf);
            }
            break;

        case MT_COLOR:
            {
                TAILQ_FOREACH(userq, &users_list, lh)
                {
                    if (memcmp(userq, user, sizeof(user_t)) == 0)
                        userq->color = atoi(msg->buf);
                }
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
        int i;
        for (i=0 ; i<BUF_SIZE ; i++)
        {
            if (str[i] == '\n')
                str[i] = '\0';
        }
        if (str[0] != '/')
        {
            msg_t * msg = get_buf(MT_MSG);
    		msg->len = BUF_SIZE;
    		strncpy(msg->buf, str, BUF_SIZE);
            send_msg(msg, MSG_SIZE);
            free_buf(msg);
        }
        else
        {
            switch(str[1])
            {
                case 'n':
                    {
                        msg_t * msg = get_buf(MT_NICK);
                        msg->len = BUF_SIZE;
                        memmove(str, str+3, strlen(str));
                        strncpy(msg->buf, str, BUF_SIZE);
                        send_msg(msg, MSG_SIZE);
                        free_buf(msg);
                    }
                    break;

                case 'c':
                    {
                        msg_t * msg = get_buf(MT_COLOR);
                        msg->len = BUF_SIZE;
                        memmove(str, str+3, strlen(str));
                        strncpy(msg->buf, str, BUF_SIZE);
                        send_msg(msg, MSG_SIZE);
                        free_buf(msg);
                    }
                    break;

                case 's':
                    {
                        show_users();
                    }
                    break;

                default:
                    printf("Commande inconnue\n");
                    printf("Commandes disponibles : \n");
                    printf("/n <pseudonyme> : change le pseudonyme de l'utilisateur\n");
                    printf("/c <couleur> : change la couleur de l'utilisateur\n");
                    printf("/s : show users\n");
                    break;
            }
        }
    }
}

void *hello_thread(void *args)
{
    while (1)
    {
        msg_t * msg = get_buf(MT_HELLO);
		msg->len = BUF_SIZE;
		strncpy(msg->buf, "hello_thread", BUF_SIZE);
        send_msg(msg, MSG_SIZE);
        free_buf(msg);
        free_user();
        sleep(5);
    }

    return NULL;
}

void free_user()
{
    user_t *user = NULL;
    TAILQ_FOREACH(user, &users_list, lh)
    {
        if ((int)time(NULL)-user->last_msg > 60)
            del_user(user);
    }
}