/*
 ============================================================================
 Name        : Peer.c
 Author      : Giacomo Persichini
 Description : This is the peer's main file
 ============================================================================
 */

#include <stdio.h>
#include <string.h> /* strcmp() */
#include <dirent.h> /* DIR* - stuff with directories */
#include <sys/stat.h> /* mkdir() - creat() */
#include <fcntl.h> /* open() */
#include <sys/mman.h> /* mmap() */
#include <unistd.h> /* write() - read() - close() - etc... */
#include <sys/socket.h> /* AF_INET - SOCK_STREAM */
#include <arpa/inet.h> /* inet_addr() */
#include <pthread.h> /* stuff with threads */
#include <errno.h> /* errno */
/* Non-standard header files */
#include <gcrypt.h> /* gcry_md_get_algo_dlen() - gcry_md_hash_buffer() */

#include "Peer.h"

volatile short int quit;

void clrscr() {
	register int i;
	for (i = 0; i < 30; i++)
		printf("\n");
}

void mypause() {
	char input[BUFFER_SIZE];
	printf("Press any key and hit Enter to continue...\n");
	scanf("%s", input);
	return;
}

unsigned long get_size_by_fd(int fd) {
    struct stat statbuf;
    if(fstat(fd, &statbuf) < 0) exit(-1);
    return statbuf.st_size;
}

int create_config_file() {
	char	ex[] = "server-ip=1.2.3.4\nserver-port=1313\nshared-folder=/home/user/shared;/home/user/public";
	int		config_file;

	if ((config_file = creat(CONFIG_FILE, S_IREAD | S_IWRITE)) == -1) {
		switch(errno) {
		case EACCES:	/* Insufficient permissions */
			fprintf(stderr, "[ERROR] Not enough permission to create an example configuration file.\n");
			break;
		default:		/* Generic error */
			fprintf(stderr, "An error has occured while creating an example configuration file.");
			break;
		}
		return -1;
	}
	else {
		if (write(config_file, ex, strlen(ex)) == -1) {
			close(config_file);
			fprintf(stderr, "Not enough permission to write an example configuration file.\n");
			return -1;
		}
		else
			close(config_file);
	}
	printf("[INFO] An example configuration file has been created. Please edit it.\n");
	return 0;
}

/* Read only positive integers **/
int i_read_config(char *field) {
	char	buffer[BUFFER_SIZE],
			a[BUFFER_SIZE];
	int		ret = 0,
			found = 0;
	FILE	*config_file = NULL;

	/* TOCTOU bug avoidance, use fopen(), not access() */
	config_file = fopen(CONFIG_FILE, "r");
	if (config_file == NULL) {
		switch (errno) {
		case ENOENT:	/* The file does not exist */
			fprintf(stderr, "[ERROR] The configuration file does not exist.\n");
			create_config_file();
			break;
		case EACCES:	/* The file is not accessible to the current user */
			fprintf(stderr, "[ERROR] Not enough permission to read the configuration file.\n");
			break;
		default:		/* Generic error */
			fprintf(stderr, "[ERROR] An error has occurred while reading the configuration file.\n");
			break;
		}
		return -1;
	}
	while (fgets(buffer, sizeof buffer, config_file) != NULL && !found)
		if (sscanf(buffer, "%[^=]=%d", a, &ret) == 2 && strcmp(field, a) == 0)
			found = 1;	/* The requested field has been found */
	fclose(config_file);
	if (found) {
		if (ret < 0) {
			fprintf(stderr, "[ERROR] 'server-port' can't be negative!\n");	/* 'Not a positive integer' error */
			return -1;
		}
		else
			return ret;
	}
	else { /* Field not found */
		fprintf(stderr, "[ERROR] Configuration file exists and is accessible, but '%s' may be missing.\n", field);
		return -1;
	}
}

void c_read_config(char *var, char *field, int *err) {
	char	buffer[BUFFER_SIZE],
			a[BUFFER_SIZE],
			b[BUFFER_SIZE];
	FILE	*config_file = NULL;
	int		found = 0;

	*err = 0;
	config_file = fopen(CONFIG_FILE, "r");
	if (config_file == NULL) {
		switch (errno) {
		case ENOENT:	/* The file does not exist */
			fprintf(stderr, "[ERROR] The configuration file does not exist.\n");
			create_config_file();
			break;
		case EACCES:	/* The file is not accessible to the current user */
			fprintf(stderr, "[ERROR] Not enough permission to read the configuration file.\n");
			break;
		default:		/* Generic error */
			fprintf(stderr, "[ERROR] An error has occurred while reading the configuration file.\n");
			break;
		}
		*err = -1;
		return;
	}
	while (fgets(buffer, sizeof buffer, config_file) != NULL && !found)
		if (sscanf(buffer, "%[^=]=%[^=]", a, b) == 2 && strcmp(field, a) == 0) {
			/* The requested field has been found */
			strcpy(var, b);
			/* There's the new-line character, it must be removed. */
			var[strlen(var)-1] = '\0';
			found = 1;
		}
	fclose(config_file);
	/* If the field has not been found it returns an empty string */
	if (!found || strcmp(var, "") == 0) {
		fprintf(stderr, "[ERROR] Configuration file exists and is accessible, but '%s' may be missing.\n", var);
		*err = -1;
	}
	return;
}

void sha1_hash(char *strout, const void *object, const size_t length) {
	register int	i;
	int				hash_len = gcry_md_get_algo_dlen(GCRY_MD_SHA1);
	unsigned char	hash[hash_len];
	char			*out = (char *) malloc(sizeof(char) * ((hash_len*2)+1)),
					*p = out;

	/* Hash it! */
	gcry_md_hash_buffer(GCRY_MD_SHA1, hash, object, length);
	for (i = 0; i < hash_len; i++, p += 2) {
		snprintf(p, 3, "%02x", hash[i]);
	}
	strcpy(strout, out);
	free(out);
}

int counth_hash_file() {
	hash_record	hrec;
	int			num,
				hash_file;

	num = 0;
	hash_file = open(HASH_FILE, O_RDONLY);
	/* No need to notice the user in case of error, just return 0 */
	if (hash_file != -1) {
		while(read(hash_file, &hrec, sizeof(hrec)) == sizeof(hrec)) {
			/* Am I reading a file made of real hash_record-s? */
			if (strlen(hrec.hash) == gcry_md_get_algo_dlen(GCRY_MD_SHA1)*2)
				num++;
		}
		close(hash_file);
	}
	return num;
}

void print_files() {
	hash_record	hrec;
	int			hash_file;

	clrscr();
	printf("############################\n");
	printf("# Shared Files:            #\n");
	printf("############################\n\n");
	hash_file = open(HASH_FILE, O_RDONLY);
	if (hash_file == -1) {
		switch(errno) {
		case EACCES:	/* Insufficient permissions */
			fprintf(stderr, "[ERROR] Not enough permissions to read the hash file.\n");
			break;
		case ENOENT:	/* File does not exist */
			fprintf(stderr, "[ERROR] Hash file has never been generated.\n");
			break;
		default:		/* Generic error */
			fprintf(stderr, "[ERROR] An error has occurred while opening the hash file.\n");
			break;
		}
	}
	else {
		while(read(hash_file, &hrec, sizeof(hash_record)) == sizeof(hash_record))
			printf("- Filename: %s\n- Hash: %s\n\n", hrec.filename, hrec.hash);
		close(hash_file);
	}
	mypause();
}

void write_hash_list() {
	DIR				*dir = NULL;
	hash_record		hrec;
	register int	i;
	int				hash_file,
					shared_file,
					err = 0;
	unsigned long	file_size;
	struct dirent	*ent = NULL;
	char			directories[BUFFER_SIZE],
					*current_dir = NULL,
					*file_buffer = NULL,
					file_path[BUFFER_SIZE],
					*hash_str = (char *) malloc(sizeof(char) * ((gcry_md_get_algo_dlen(GCRY_MD_SHA1) * 2) + 1));

	c_read_config(directories, "shared-folder", &err);
	if (err == 0) {
		current_dir = strtok(directories, ";");
		hash_file = open(HASH_FILE, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
		if (hash_file == -1) {
			switch (errno) {
			case EACCES:			/* Insufficient permissions */
				fprintf(stderr, "[ERROR] Not enough permissions to create the hash file.\n");
				break;
			default:				/* Generic error */
				fprintf(stderr, "[ERROR] An error has occurred while opening the hash file.\n");
				break;
			}
			mypause();
			return;
		}
		while (current_dir != NULL) {
			for (i = 0; i < 2; i++) {
				dir = opendir(current_dir);
				if (dir == NULL) {
					switch (errno) {
					case EACCES:	/* Insufficient permissions */
						fprintf(stderr, "[ERROR] Not enough permissions to read the shared folder '%s'.\n", current_dir);
						mypause();
						return;
					default:
						fprintf(stderr, "[ERROR] An error has occurred while trying to read the shared folder '%s'.\n", current_dir);
						printf("[INFO] The shared folder may not exist, trying to create it...\n");
						if(mkdir(current_dir, S_IRWXU | S_IRWXG | S_IROTH) == -1)
							switch (errno) {
							case EACCES:
								fprintf(stderr, "[ERROR] Not enough permissions to create the folder.\n");
								mypause();
								return;
							default:
								fprintf(stderr, "[ERROR] An error has occurred while trying to create the folder.\n");
								mypause();
								return;
							}
						else
							printf("[INFO] Created! Trying to read it again...\n");
						break;
					}
				}
				else
					break;
			}
			while ((ent = readdir(dir)) != NULL) {
				if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
					/* Creating the relative file path */
					strcpy(file_path, current_dir);
					strcat(file_path, "/");
					strcat(file_path, ent->d_name);
					shared_file = open(file_path, O_RDONLY);
					if (shared_file == -1) {
						switch (errno) {
						case EACCES:	/* Insufficient permissions */
							fprintf(stderr, "[ERROR] Not enough permissions to open file: %s.\n", file_path);
							break;
						default:		/* Generic error */
							fprintf(stderr, "[ERROR] An error has occurred while trying to read the file: %s.\n", file_path);
							break;
						}
						continue;
					}
					/* Get file size by file descriptor */
					file_size = get_size_by_fd(shared_file);
					if (file_size == 0) {
						fprintf(stderr, "[ERROR] File '%s' is 0 bytes, can't hash it.\n", file_path);
						continue;
					}
					/* I need to put the file in memory to hash it */
					file_buffer = mmap(0, file_size, PROT_READ, MAP_SHARED, shared_file, 0);
					if (*file_buffer == -1) {
						fprintf(stderr, "[ERROR] Unable to map %s into memory.\n", file_path);
						close(shared_file);
						continue;
					}
					strcpy(hrec.filename, file_path);
					sha1_hash(hash_str, file_buffer, file_size);
					strcpy(hrec.hash, hash_str);
					if (write(hash_file, &hrec, sizeof(hrec)) == -1)
						fprintf(stderr, "[ERROR] Unable to write record '%s' into hash file. Freeing memory and proceeding.\n", file_path);
					close(shared_file);
					munmap(file_buffer, file_size);
				}
			}
			closedir(dir);
			/* Next directory to share */
			current_dir = strtok(NULL, ";");
		}
		close(hash_file);
		free(ent);
		free(hash_str);
		printf("[INFO] Hash list generated.\n");
	}
	mypause();
	return;
}

int is_connected(int socket) {
	if (send(socket, NULL, 0, 0) == -1)
		return -1;
	else
		return 0;
}

int handshake(int type, int *socket) {
	char	buffer[1024],
			msg[9],
			p2s[] = "HELLO",
			p2p[] = "HELLOPEER";

	if (is_connected(*socket) == -1)
		return -1;

	if (type == 0)
		strcpy(msg, p2s);
	else
		strcpy(msg, p2p);

	if (send(*socket, msg, strlen(msg), 0) == -1)
		return -1;
	bzero(buffer, 1024);
	while (read(*socket, buffer, sizeof(buffer)) > 0) {
		if (strcmp(buffer, msg) != 0) {
			send(*socket, "NO", 2, 0); /* No need to return -1 at this point */
			close(*socket);
			*socket = -1;
			return -1;
		}
		break;
	}
	return 0;
}

int send_file(char *filepath, int *socket) {
	char			buffer[BUFFER_SIZE];
	size_t			bytes;
	int				file;
	unsigned long	length;

	if (is_connected(*socket) == -1)
		return -2;

	file = open(filepath, O_RDONLY);
	if (file != -1) {
		bzero(buffer, BUFFER_SIZE);
		length = htonl((uint32_t) get_size_by_fd(file));
		if (send(*socket, &length, sizeof(length), 0) == -1)
			return -2;
		while ((bytes = read(file, buffer, sizeof(buffer))) > 0)
			if (send(*socket, buffer, bytes, 0) == -1)
				return -2;
		close(file);
	}
	else
		return -1;
	return 0;
}

int receive_file(char *filepath, int *socket) {
	char			buffer[BUFFER_SIZE];
	int				recvd_flag = 0,
					fp;
	size_t			bytes = 0;
	unsigned long	length = 0;
	unsigned long	bytecount = 0;

	if (is_connected(*socket) == -1)
		return recvd_flag;

	while (read(*socket, &length, sizeof(length)) == sizeof(length)) {
		length = ntohl(length);
		printf("[INFO] File size: %lu bytes.\n", length);
		break;
	}

	fp = open(filepath, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	if (fp == -1) {
		switch (errno) {
		case EACCES:			/* Insufficient permissions */
			fprintf(stderr, "[ERROR] Not enough permissions to create the received file.\n");
			break;
		default:				/* Generic error */
			fprintf(stderr, "[ERROR] An error has occurred while opening the file.\n");
			break;
		}
		mypause();
		return recvd_flag;
	}

	bzero(buffer, BUFFER_SIZE);
	while ((bytes = read(*socket, buffer, sizeof(buffer))) > 0) {
		bytecount += bytes;
		write(fp, buffer, bytes);
		bzero(buffer, BUFFER_SIZE);
		if (bytecount >= length) {
			printf("[INFO] File transfer completed.\n");
			recvd_flag = 1;
			break;
		}
	}
	close(fp);
	return recvd_flag;
}

void conn_to_server(int *socket2server) {
	int		server_port,
			err = 0;
	struct	sockaddr_in server;
	char	server_ip[15] = "";

	if (counth_hash_file() == 0) {
		fprintf(stderr, "[ERROR] You must share some files! Generate a hash list and try again.\n");
		mypause();
		return;
	}

	/* Check if connections is already established */
	if (is_connected(*socket2server) == 0) {
		fprintf(stderr, "[ERROR] Already connected!\n");
		mypause();
		return;
	}

	/* Retrieve server's info */
	c_read_config(server_ip, "server-ip", &err);
	server_port = i_read_config("server-port");

	if (server_port < 0 || err != 0) {
		mypause();
		return;
	}

	/* Connection to server */
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(server_ip);
	server.sin_port = htons(server_port);

	/* I'm going to cast sockaddr_in in sockaddr, I need to do this */
	memset(&server.sin_zero, '\0', sizeof(server.sin_zero));

	if ((*socket2server = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("[ERROR] socket() syscall failed");
		mypause();
		return;
	}

	if (connect(*socket2server, (struct sockaddr *) &server, sizeof(server)) == -1) {
		perror("[ERROR] Connection failed");
		*socket2server = -1;
		mypause();
		return;
	}

	/* Hand-shake */
	if (handshake(0, socket2server) == -1) {
		fprintf(stderr, "[ERROR] Hand-shake failed.\n");
		mypause();
		return;
	}

	/* Send hash file */
	err = send_file("hash", socket2server);
	if (err == -1) {
		fprintf(stderr, "[ERROR] Could not open file to send.\n");
		mypause();
		return;
	}
	else if (err == -2) {
		fprintf(stderr, "[ERROR] Could not send hash file, send() failed.\n");
		mypause();
		return;
	}
}

void download_file(int *socket2server) {
	char	buffer[BUFFER_SIZE],
			hash[41],
			hash_cmd[46] = "HASH-",
			filename[BUFFER_SIZE],
			*tok = NULL,
			filepath[18] = "downloads/";
	int		sock2peer;
	struct	sockaddr_in peer;

	if (is_connected(*socket2server) == -1)
		return;

	clrscr();
	printf("############################\n");
	printf("# Download a file:         #\n");
	printf("############################\n\n");
	printf("Hash: ");
	scanf("%s", hash);
	printf("Save as: ");
	scanf("%s", filename);
	strcat(hash_cmd, hash);
	if (send(*socket2server, hash_cmd, 46, 0) == -1) {
		perror("[ERROR] Couldn't request the hash to the server");
		mypause();
		return;
	}
	else
		printf("[INFO] Hash requested to server.\n");

	bzero(buffer, 1024);
	while (read(*socket2server, buffer, sizeof(buffer)) > 0) {
		tok = strtok(buffer, "-");
		if (strcmp(tok, "NOTFOUND") == 0) {
			printf("[INFO] Server responded. Hash not found!\n");
			mypause();
			return;
		}
		else if (strcmp(tok, "FOUND") == 0) {
			tok = strtok(NULL, "-");
			printf("[INFO] Server responded. Owner: %s\n", tok);
			break;
		}
	}

	if ((sock2peer = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			perror("[ERROR] socket() call failed");
			mypause();
			return;
	}

	peer.sin_family = AF_INET;
	peer.sin_addr.s_addr = inet_addr(tok);
	peer.sin_port = htons(25546);

	/* I'm going to cast sockaddr_in in sockaddr, I need to do this */
	memset(&peer.sin_zero, '\0', sizeof(peer.sin_zero));

	if (connect(sock2peer, (struct sockaddr *) &peer, sizeof(peer))==-1) {
		perror("[ERROR] connect() call failed");
		mypause();
		return;
	}

	/* Hand-shake */
	if (handshake(1, &sock2peer) == -1) {
		printf("[ERROR] Hand-shake failed.\n");
		close(sock2peer);
		mypause();
		return;
	}

	if (send(sock2peer, hash_cmd, 46, 0) == -1) {
		perror("[ERROR] Couldn't request the hash to the peer");
		close(sock2peer);
		mypause();
		return;
	}

	strcat(filepath, filename);
	if (receive_file(filepath, &sock2peer) == 0)
		fprintf(stderr, "[ERROR] Couldn't receive the file.\n");

	close(sock2peer);
	mypause();
}

void peer_listener() {
	fd_set				master,
						read_fds;
	socklen_t			client_len;
	hash_record			x;
	struct sockaddr_in	server,
						client;
	struct timeval		timeout;
	char				buffer[BUFFER_SIZE],
						*tok = NULL;
	int					fdmax,
						listener,
						newfd,
						selectval,
						bytes,
						yes = 1, /* for setsockopt() */
						client_num = 0,
						found = 0,
						i,
						fp,
						err = 0;

	/* Set the timeout to 1 second */
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	/* Clear the master and temp sets */
	FD_ZERO(&master);
	FD_ZERO(&read_fds);

	if ((listener = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("[ERROR] Listener: socket() call failed");
		mypause();
		pthread_exit(NULL);
	}

	/* This is to avoid "address is already in use" error messages */
	if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		perror("[ERROR] Listener: setsockopt() call failed");
		mypause();
		pthread_exit(NULL);
	}

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(25546);

	/* I'm going to cast sockaddr_in in sockaddr, I need to do this */
	memset(&server.sin_zero, '\0', sizeof(server.sin_zero));

	if (bind(listener, (struct sockaddr *) &server, sizeof(server)) == -1) {
		perror("[ERROR] Listener: bind() call failed");
		mypause();
		pthread_exit(NULL);
	}

	if (listen(listener, 1) == -1) {
		perror("[ERROR] Listener: listen() call failed");
		mypause();
		pthread_exit(NULL);
	}

	FD_SET(listener, &master);
	fdmax = listener;

	while (1) {
		read_fds = master;

		selectval = select(fdmax+1, &read_fds, NULL, NULL, &timeout);
		if (selectval < 0) {
			perror("[ERROR] Listener: select() call failed");
			mypause();
			pthread_exit(NULL);
		}
		else if (selectval == 0) {
			/* timeout */
			if (quit) {
				break;
			}
			else
				continue;
		}

		/* Look for data to be read from existing connections */
		for (i = 0; i <= fdmax; i++) {
			if (FD_ISSET(i, &read_fds)) { /* Found some data */
				/*
				 * 1 - There's a new connection to handle
				 */
				if (i == listener) {
					client_len = sizeof(client);

					if ((newfd = accept(listener, (struct sockaddr *) &client, &client_len)) == -1) {
						perror("[ERROR] Listener: accept() call failed");
					}
					else { /* Let's test the client before adding it to the set */
						client_num++;
						if (client_num > 1) { /* There can only be one connected client, kick the new one */
							close(newfd);
							client_num--;
							break;
						}
						if (handshake(1, &newfd) == -1) { /* If handshake fails, kick the client */
							client_num--;
							break;
						}

						/* If we're here there's a genuine client to serve */
						FD_SET(newfd, &master);
						if(newfd > fdmax)
							fdmax = newfd;
					}
				}
				/*
				 * 2 - An already connected client is sending some data
				 */
				else {
					if ((bytes = read(i, buffer, sizeof(buffer))) <= 0) {
						/* Client closed the connection or an error happened */
						close(i);
						client_num--;
						FD_CLR(i, &master);
					}
					else {
						/* See what the client needs and send it */
						tok = strtok(buffer, "-");;
						if(strcmp(tok, "HASH") == 0) {
							tok = strtok(NULL, "-");
							fp = open(HASH_FILE, O_RDONLY);
							if (fp != -1) {
								while ((read(fp, &x, sizeof(hash_record))) == sizeof(hash_record)) {
									if (strcmp(x.hash, tok) == 0) {
										found = 1;
										break;
									}
								}
								close(fp);
							}
							else
								fprintf(stderr, "[ERROR] Couldn't open the hash file while sending a shared file.\n");
						}
						if (found == 1) {
							err = send_file(x.filename, &i);
							if (err == -1)
								fprintf(stderr, "[ERROR] Could not open file to send.\n");
							else if (err == -2)
								fprintf(stderr, "[ERROR] Could not send hash file, send() failed.\n");
						}

						/* Done, clear everything and serve another client */
						found = 0;
						client_num--;
						close(i);
						FD_CLR(i, &master);
					}
				}
			}
		}
	}
	close(listener);
	/* Disconnecting all the clients */
	for (i = 0; i <= fdmax; i++)
		if (FD_ISSET(i, &master))
			close(i);
	pthread_exit(NULL);
}

void user_interface(int *socket2server) {
	short int	choice = 0,
				exit = 0;

	while (!exit) {
		clrscr();
		printf("############################\n");
		printf("# Peer %2.2f                #\n", _VERSION_);
		printf("############################\n");
		printf("# Stats: #\n");
		printf("- Shared files:\t%d\n", counth_hash_file());
		printf("############################\n\n\n\n\n\n");
		printf("# Menu: #\n");
		if (is_connected(*socket2server) == -1)
			printf("1) Connect\n");
		else
			printf("1) Disconnect\n");
		printf("2) List shared files\n");
		printf("3) Generate hash list\n");
		if (is_connected(*socket2server) == 0)
			printf("4) Download file\n");
		printf("\n0) Exit\n\n\n");
		printf("Your choice: ");
		scanf("%hd", &choice);
		switch (choice) {
		case 0:
			exit = 1;
			if (is_connected(*socket2server) == 0)
				close(*socket2server);
			break;
		case 1:
			if (is_connected(*socket2server) == -1)
				conn_to_server(socket2server);
			else
				close(*socket2server);
			break;
		case 2:
			print_files();
			break;
		case 3:
			write_hash_list();
			break;
		case 4:
			if (is_connected(*socket2server) == 0)
				download_file(socket2server);
			break;
		default:
			choice = 0;
			break;
		}
	}
	quit = 1; /* Tell the listener thread to terminate as soon as possible */
	pthread_exit(NULL);
}

int main() {
	pthread_t	listener,
				ui;
	int			socket2server;

	quit = 0;

	if (pthread_create(&listener, NULL, (void *) &peer_listener, NULL) < 0) {
		perror("[ERROR] Couldn't start listener thread");
		return -1;
	}

	if (pthread_create(&ui, NULL, (void *) &user_interface, &socket2server) < 0) {
		perror("[ERROR] Couldn't start UI thread");
		return -1;
	}

	/*
	 * It is important to wait for every thread to terminate
	 */
	pthread_join(ui, NULL);
	pthread_join(listener, NULL);

	printf("Thank you for using Peer %2.2f\n", _VERSION_);
	return 0;
}
