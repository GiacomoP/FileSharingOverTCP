/*
 * Server.h
 *
 *      Author: Giacomo Persichini
 */

#ifndef SERVER_H_
#define SERVER_H_

#define BUFFER_SIZE 1024
#define _VERSION_ 0.01
#define CONFIG_FILE "config"

typedef struct hash_record {
	char hash[41];
	char filename[1024];
} hash_record;

int create_config_file();
int i_read_config(char *);
void c_read_config(char *, char *, int *);
int is_connected(int);
int handshake(int *);
int receive_file(char *, int *);
void server_listener();
void user_input_handler();

#endif /* SERVER_H_ */
