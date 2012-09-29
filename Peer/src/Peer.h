/*
 * Peer.h
 *
 *      Author: Giacomo Persichini
 */

#ifndef PEER_H_
#define PEER_H_

#define _VERSION_ 0.01
#define BUFFER_SIZE 1024
#define CONFIG_FILE "config"
#define HASH_FILE "hash"

typedef struct hash_record {
	char hash[41];
	char filename[1024];
} hash_record;

void clrscr();
void mypause();
unsigned long _get_size_by_fd(int);
int create_config_file();
int i_read_config(char *);
void c_read_config(char *, char *, int *);
void sha1_hash(char *, const void *, const size_t);
int counth_hash_file();
void print_files();
void write_hash_list();
int is_connected(int);
int handshake(int, int *);
int send_file(char *, int *);
int receive_file(char *, int *);
void conn_to_server(int *);
void download_file(int *);
void peer_listener();
void user_interface(int *);

#endif /* PEER_H_ */
