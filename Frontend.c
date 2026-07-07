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
static void *(*volatile memset_volatile)(void *, int, size_t) = memset;

static void secure_zero(void *buf, size_t len) {
    memset_volatile(buf, 0, len);
}
static void read_line(char *buf, size_t cap) {
    if (fgets(buf, (int)cap, stdin) == NULL) {
        buf[0] = '\0';
        return;
    }
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }
}