# Discussion distribuée

LEROY Damien

## How to

### Install

Compilation à l'aide d'un makefile : `make`

### Use

Pour l'exécuter : `./dicussion`  
Il suffit ensuite simplement d'entrer son message et de valider par un retour à la ligne.  
Les commandes disponibles sont : 
* `/e` Déconnexion
* `/n pseudonyme` Modifier son pseudo
* `/c 30` Modifier sa couleur (entre 30 et 37)
* `/s` Affiche la liste des utilisateurs

## About

Le programme permet de communiquer avec tous les autres utilisateurs du réseau. Les messages sont passés en broadcast.  
Il n'y a donc aucune garantie de réception de message. Un message peut alors être perdu si l'une des machines n'est plus connecté au réseau au moment de l'envoie.  
Un message est envoyé toutes les 5 secondes pour notifié les autres utilisateurs de sa présence. Un système de vérification y a été ajouté pour savoir si une personne est absente depuis plus d'une minute.

Attention, les messages ne sont pas chiffrés, et toutes les personnes du réseau réceptionnent les messages, même sans le client. Il est par exemple possible de voir les message grâce à `tcpdump`.  
Il n'y a aucune protection contre le flood, aucune restriction de messages par seconde n'a été implémenté.
