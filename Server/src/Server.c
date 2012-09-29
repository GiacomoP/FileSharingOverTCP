/*
 ============================================================================
 Name        : Server.c
 Author      : Giacomo Persichini
 Description : This is the server's main file
 ============================================================================
 */

#include <stdio.h>
#include <string.h> /* strcmp() */
#include <dirent.h> /* DIR* - things with directories */
#include <sys/stat.h> /* mkdir() - creat() */
#include <fcntl.h> /* open() */
#include <unistd.h> /* close() - read() - write() - etc... */
#include <sys/socket.h> /* AF_INET - SOCK_STREAM */
#include <sys/wait.h> /* waitpid() - WNOHANG */
#include <arpa/inet.h> /* inet_addr() */
#include <pthread.h> /* stuff with threads */
#include <errno.h> /* errno */

#include "Server.h"

volatile short int quit;

int create_config_file() {
	char	ex[] = "server-ip=1.2.3.4\nserver-port=1313\nmax-connections=50";
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

int is_connected(int socket) {
	if (send(socket, NULL, 0, 0) == -1)
		return -1;
	else
		return 0;
}

int handshake(int *socket) {
	char	buffer[1024],
			msg[] = "HELLO";

	if (is_connected(*socket) == -1)
		return -1;

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
		return recvd_flag;
	}

	bzero(buffer, BUFFER_SIZE);
	while ((bytes = read(*socket, buffer, sizeof(buffer))) > 0) {
		bytecount += bytes;
		write(fp, buffer, bytes);
		bzero(buffer, BUFFER_SIZE);
		if (bytecount >= length) {
			recvd_flag = 1;
			break;
		}
	}
	close(fp);
	return recvd_flag;
}

void server_listener() {
	int						listener,
							server_port,
							max_connections,
							err = 0,
							yes = 1, /* for setsockopt() */
							fdmax,
							newfd,
							selectval,
							i,
							client_num = 0,
							found = 0,
							fp;
	char					server_ip[15] = "",
							*tok = NULL,
							found_cmd[21] = "FOUND-",
							path[BUFFER_SIZE],
							ip[INET_ADDRSTRLEN],
							buffer[BUFFER_SIZE];
	struct sockaddr_in		server,
							client, *tmp = NULL;
	struct sockaddr_storage	storage;
	socklen_t				client_len = sizeof(client),
							storage_len = sizeof(storage);
	struct timeval			timeout;
	fd_set					master,
							read_fds;
	DIR						*dir;
	hash_record				x;
	struct dirent			*ent = NULL;

	/* Set the timeout to 1 second */
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	/* Clear the master and temp sets */
	FD_ZERO(&master);
	FD_ZERO(&read_fds);

	if ((listener = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("[ERROR] Listener: socket() call failed");
		pthread_exit(NULL);
	}

	/* This is to avoid "address is already in use" error messages */
	if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		perror("[ERROR] Listener: setsockopt() call failed");
		pthread_exit(NULL);
	}

	printf("Opening Server - v%2.2f\n\n[INFO] Quit sequence: 0 + [Enter]\n\n[INFO] Fetching data from config file...\n", _VERSION_);

	c_read_config(server_ip, "server-ip", &err);
	server_port = i_read_config("server-port");
	max_connections = i_read_config("max-connections");

	if (server_port < 0 || err != 0 || max_connections < 0)
		pthread_exit(NULL);

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(server_ip);
	server.sin_port = htons(server_port);

	/* I'm going to cast sockaddr_in in sockaddr, I need to do this */
	memset(&server.sin_zero, '\0', sizeof(server.sin_zero));

	/* Address Binding */
	if (bind(listener, (struct sockaddr *) &server, sizeof(server)) == -1) {
		perror("[ERROR] Listener: bind() call failed");
		pthread_exit(NULL);
	}

	if (listen(listener, max_connections) == -1) {
		perror("[ERROR] Listener: listen() call failed");
		pthread_exit(NULL);
	}

	printf("[INFO] IP: %s\n[INFO] Port: %d\n[INFO] Max Conn.: %d\n\n[INFO] The server is now listening.\n", server_ip, server_port, max_connections);

	FD_SET(listener, &master);
	fdmax = listener;

	/* Clients connection management starts here */
	while (1) {
		read_fds = master;

		selectval = select(fdmax+1, &read_fds, NULL, NULL, &timeout);
		if (selectval < 0) {
			perror("[ERROR] Listener: select() call failed");
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
					if ((newfd = accept(listener, (struct sockaddr *) &client, &client_len)) == -1)
						perror("[ERROR] Listener: accept() call failed");
					else { /* Let's test the client before adding it to the set */
						client_num++;
						if (client_num > max_connections) { /* Check if current client # respects max_connections */
							close(newfd);
							client_num--;
							continue;
						}

						printf("[INFO] New connection (%s).\n", inet_ntoa(client.sin_addr));

						if (handshake(&newfd) == -1) { /* If handshake fails, kick the client */
							printf("[INFO] Hand-shake failed!\n[INFO] Closed connection (%s).\n", inet_ntoa(client.sin_addr));
							client_num--;
							continue;
						}

						/* If we're here there's a genuine client, I expect a list of hashesh from it */
						bzero(path, BUFFER_SIZE);
						strcpy(path, "db/");
						strcat(path, inet_ntoa(client.sin_addr));
						if (receive_file(path, &newfd))
							printf("[INFO] File transfer completed (%s).\n", inet_ntoa(client.sin_addr));
						else
							printf("[INFO] Couldn't get the list of hashes (%s).\n", inet_ntoa(client.sin_addr));

						FD_SET(newfd, &master);
						if(newfd > fdmax)
							fdmax = newfd;
						printf("[INFO] Peer verified (%s).\n", inet_ntoa(client.sin_addr));
					}
				}
				/*
				 * 2 - An already connected client is sending some data
				 */
				else {
					/* Retrieving client's data from socket descriptor */
					if (getpeername(i, (struct sockaddr *) &storage, &storage_len) == -1) {
						fprintf(stderr, "[ERROR] An error occurred while retrieving the IP address of a client.\n");
						continue;
					}
					tmp = (struct sockaddr_in *) &storage;
					inet_ntop(AF_INET, &tmp->sin_addr, ip, sizeof ip);

					bzero(buffer, BUFFER_SIZE);
					if (read(i, buffer, sizeof(buffer)) <= 0) {
						/* Client closed the connection or an error happened */
						printf("[INFO] Closed connection (%s).\n", ip);
						bzero(path, BUFFER_SIZE);
						strcpy(path, "db/");
						strcat(path, ip);
						if (remove(path) != 0) {
							fprintf(stderr, "[ERROR] Couldn't delete client's hash list file, ");
							switch(errno) {
							case EACCES:
								fprintf(stderr, "not enough permissions.\n");
								break;
							case EBUSY:
								fprintf(stderr, "file is busy.\n");
								break;
							case ENOENT:
								fprintf(stderr, "file does not exist.\n");
								break;
							default:
								fprintf(stderr, "an error occurred.\n");
								break;
							}
						}
						close(i);
						client_num--;
						FD_CLR(i, &master);
					}
					else {
						tok = strtok(buffer, "-");
						if (strcmp(tok, "HASH") == 0) {
							tok = strtok(NULL, "-");
							dir = opendir("db");
							if (dir == NULL) {
								fprintf(stderr, "[ERROR] Couldn't open 'db/' directory, ");
								switch(errno) {
								case EACCES:
									fprintf(stderr, "not enough permissions.\n");
									break;
								case ENOENT:
									fprintf(stderr, "directory does not exist.\n");
									break;
								default:
									fprintf(stderr, "an error has occurred.\n");
									break;
								}
							}
							else  {
								/*
								 * A client sent an hash, find who's sharing it
								 */
								while ((ent = readdir(dir)) != NULL) {
									if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0 && strcmp(ent->d_name, ip) != 0) {
										bzero(path, BUFFER_SIZE);
										strcpy(path, "db/");
										strcat(path, ent->d_name);
										fp = open(path, O_RDONLY);
										if (fp == -1) {
											switch(errno) {
											case EACCES:	/* Insufficient permissions */
												fprintf(stderr, "[ERROR] Not enough permissions to read the hash file.\n");
												break;
											default:		/* Generic error */
												fprintf(stderr, "[ERROR] An error has occurred while opening the hash file.\n");
												break;
											}
										}
										else {
											while (read(fp, &x, sizeof(hash_record)) == sizeof(hash_record)) {
												if (strcmp(x.hash, tok) == 0) {
													found = 1;
													break;
												}
											}
											close(fp);
										}
										if (found == 1)
											break;
									}
								}
								closedir(dir);
							}
							if (found == 1) {
								strcat(found_cmd, ent->d_name);
								if (send(i, found_cmd, 21, 0) == -1)
									perror("[ERROR] Couldn't tell the peer I found the hash, send() failed");
							}
							else
								if (send(i, "NOTFOUND", 8, 0) == -1)
									perror("[ERROR] Couldn't tell the peer I haven't found the hash, send() failed");
						}
						else
							break; /* Client sent an unrecognized command */
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

void user_input_handler() {
	short int	choice = -1;

	while (choice != 0) {
		scanf("%hd", &choice);
		if (choice == 0)
			quit = 1;
	}
	printf("Terminating...\n");
	pthread_exit(NULL);
}

int main() {
	pthread_t	listener,
				ui;

	if (pthread_create(&listener, NULL, (void *) &server_listener, NULL) < 0) {
		perror("[ERROR] Couldn't start listener thread");
		return -1;
	}

	if (pthread_create(&ui, NULL, (void *) &user_input_handler, NULL) < 0) {
		perror("[ERROR] Couldn't start UI thread");
		return -1;
	}

	/*
	 * It is important to wait for every thread to terminate
	 */
	pthread_join(ui, NULL);
	pthread_join(listener, NULL);

	printf("Thank you for using Server %2.2f\n", _VERSION_);
	return 0;
}
