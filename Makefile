CC = gcc
CFLAGS = -Wall -Wextra

PortScanner: PortScanner
	$(CC) $(CFLAGS) -o PortScanner PortScanner.c
