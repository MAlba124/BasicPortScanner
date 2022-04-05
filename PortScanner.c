/* 
	This program is a very basic port scanner.
	It should not be used in real-life situations and the
	output should not be trustable as I am sure there are
	a lot of mistakes in this code.

	Free to use and distrubute as long as I (malba) is mentioned :)
*/

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Remove comment for (some) debug information
//#define DEBUG

#define TOP_PORT 65536

typedef struct {
	unsigned int port;
	unsigned int spesPort;
	unsigned int ipProvided;
	unsigned int exit;
	unsigned int scanAll;
	unsigned int threads;
	unsigned int openPorts;
	unsigned int closedPorts;
	unsigned short d;
	unsigned short open;
	char *ip;
} Target;

int _len(const char *str) {

	int count = 0;
	while(str[count] != '\0') {
		count++;
	}

	return count;
}

int _equal(const char *strOne, const char *strTwo) {
	
	int lenStrOne = _len(strOne);
	if(lenStrOne != _len(strTwo)) {
		return 0;
	}


	for(int i = 0; i < lenStrOne; i++) {
		if(strOne[i] != strTwo[i]) {
			return 0;
		}
	}

	return 1;
}

int _in(char const *args[], char *comp, int len) {
	
	for(int i = 0; i <= len-1; i++) {
		if(_equal(args[i], comp)) {
			return i;
		}
	}

	return -1;
}

int _isnum(const char *str) {

	int isnum = 0;
	int i = 0;

	while(str[i] != '\0') {
		if(str[i] <= '9' && str[i] >= '0') {
			isnum = 1;
		} else {
			return 0;
		}
		i++;
	}

	return isnum;
}

Target *scanPort(Target *t, unsigned int port) {

	int connection_status, sockfd;
    struct sockaddr_in servaddr;
    struct timeval tv; 
    fd_set myset;
    socklen_t lon;
    int valopt;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_addr.s_addr = inet_addr(t->ip);
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);

    long arg;
    if ((arg = fcntl(sockfd, F_GETFL, NULL)) < 0) {
    	close(sockfd);
    	return t;
    }

    arg |= O_NONBLOCK; 
	if(fcntl(sockfd, F_SETFL, arg) < 0) {
		close(sockfd);
		return t;
	}

    connection_status = connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if(connection_status < 0) {
    	if (errno == EINPROGRESS) {
    		do {
		    	tv.tv_sec = 10; // 10 seconds time out 
				tv.tv_usec = 0; 
				FD_ZERO(&myset);
				FD_SET(sockfd, &myset); 
				connection_status = select(sockfd+1, NULL, &myset, NULL, &tv); 
				if (connection_status < 0 && errno != EINTR) { 
					break;
				} else if (connection_status > 0) {
			    	
					lon = sizeof(int); 
						if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon) < 0) { 
							break;
					}

					if(!valopt) {
				    	if(t->d == 0) {
				    		fprintf(stdout, "Discovered open port(s)\n\nPort : Service : State\n");
				    		t->d = 1;
				    	}

				        char host[128];
				        char service[128];

				        getnameinfo((struct sockaddr*)&servaddr, sizeof servaddr, host, (sizeof host), service, sizeof service, 0);

				        fprintf(stdout, "%d : %s : Open\n", port, service);
				    	
				    	close(sockfd);

				    	if(t->spesPort) {
				    		t->open = 1;
			    		}
			    		t->openPorts++;
				    	return t;
			    	} else {
			    		t->closedPorts++;
			    		close(sockfd);
			    		return t;
			    	}
		   		}
	   		} while(1);
	    }
	}
    close(sockfd);
    return t;
}

Target *scanAll(Target *t) {
	
	#ifdef DEBUG
		fprintf(stdout, "[DEBUG] Starting port scan...\n");
	#endif

	t->d = 0;

	for(unsigned int port = 0; port < TOP_PORT; port++) {
		scanPort(t, port);
    }

	#ifdef DEBUG
		fprintf(stdout, "[DEBUG] Port scan finished\n");
	#endif

	return t;
}

Target *parse(Target *t, int argLen, char const *args[]) {

	#ifdef DEBUG
		fprintf(stdout, "[DEBUG] Parsing command line arguments\n");
	#endif

	t->spesPort = 0;
	t->ipProvided = 0;
	if(argLen >= 1) {
		if((argLen < 3) && _in(args, "-h", argLen) == -1) {
			fprintf(stdout, "Missing arguments!\n");
			t->exit = 1;
			return t;
		} else if(_equal(args[1], "-h")) {
			fprintf(stdout, "Help\n"); // Too lazy to add anything here
			t->exit = 1;
			return t;
		} else {
			for(int i = 0; i <= argLen-1; i++) {
				if(_equal(args[i], "-ip")) {
					if(t->ipProvided == 0) {
						if (i == argLen) {
							t->exit = 1;
						} else {
							t->ip = (char *) args[i+1];
							t->ipProvided = 1;
						}
					}
				} else if(_equal(args[i], "-p")) {
					if(t->spesPort == 0) {
						if (i == argLen) {
							t->exit = 1;
						} else {
							if(_isnum(args[i+1])) {
								int port = strtol(args[i+1], NULL, 10);
								if(port <= 0) {
									fprintf(stdout, "Invalid port number!");
									t->exit = 1;
									return t;
								}
								t->port = (unsigned int) port;
								t->spesPort = 1;
							}
						}
					}
				}
			}
			if(t->spesPort == 0) {
				t->scanAll = 1;
			} else if (t->spesPort == 1) {
				t->scanAll = 0;
			} else {
				t->exit = 1;
			}
			return t;
		}
	} else {
		fprintf(stdout, "Missing arguments!\n-h for help\n");
	}
	t->exit = 1;
	return t;
}

int main(int argc, char const *argv[]) {

    clock_t time;
    time = clock();

	#ifdef DEBUG
		fprintf(stdout, "DEBUG MODE ENABLED\n");
	#endif

	Target *t = malloc(sizeof(Target)); 
	parse(t, argc, argv);

	if(t->exit == 1) {
		#ifdef DEBUG
			fprintf(stdout, "[DEBUG] Exiting...\n");
		#endif
		return 1;
	} else if (t->scanAll == 1) {
		fprintf(stdout, "Port is not set, scanning all (%d) ports on %s\n\n", TOP_PORT, t->ip);
		scanAll(t);
	} else if(t->spesPort == 1) {
		fprintf(stdout, "Scanning port %d on %s\n\n", t->port, t->ip);
		scanPort(t, t->spesPort);
		if(t->open) {
			t->openPorts++;
		} else {
			fprintf(stdout, "Port %d on target system looks to be closed\n", t->port);
			t->closedPorts++;
		}
	}

	fprintf(stdout, "\nTotal ports scanned: %d  Total open ports: %d  Total closed ports: %d\n",
		(t->openPorts+t->closedPorts), t->openPorts, t->closedPorts);

	free(t);
    
    time = clock() - time;
    fprintf(stdout, "Runtime: %fs\n", ((float)time) / CLOCKS_PER_SEC);

	#ifdef DEBUG
		fprintf(stdout, "[DEBUG] Exiting...\n");
	#endif
	return 0;
}
