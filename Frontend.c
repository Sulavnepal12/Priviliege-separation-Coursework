#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>

#define SOCKET_PATH   "/tmp/authsock"
#define MAX_USERNAME  64
#define MAX_PASSWORD  64

typedef struct {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
} auth_request_t;

typedef struct {
    int  success;
    char message[128];
} auth_response_t;