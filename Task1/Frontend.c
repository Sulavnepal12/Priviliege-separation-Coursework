#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH   "/tmp/authsock_secure"
#define MAX_USER_LEN  32
#define MAX_PASS_LEN  64

typedef struct {
    char username[MAX_USER_LEN];
    char password[MAX_PASS_LEN];
} auth_request_t;

typedef struct {
    int  success;
    char message[64];
} auth_response_t;

static void *(*volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_zero(void *buf, size_t len) {
    if (buf != NULL && len > 0) {
        secure_memset_ptr(buf, 0, len);
    }
}

static int read_password_no_echo(char *buf, size_t buflen) {
    struct termios oldt, newt;
    int fd = STDIN_FILENO;

    if (tcgetattr(fd, &oldt) != 0) {
        perror("tcgetattr");
        return -1;
    }
    newt = oldt;
    newt.c_lflag &= ~ECHO;

    if (tcsetattr(fd, TCSAFLUSH, &newt) != 0) {
        perror("tcsetattr");
        return -1;
    }

    printf("Password: ");
    fflush(stdout);

    int ok = 1;
    if (fgets(buf, (int)buflen, stdin) == NULL) {
        ok = 0;
    } else {
        size_t n = strlen(buf);
        if (n > 0 && buf[n - 1] == '\n') buf[n - 1] = '\0';
    }
    printf("\n");

    tcsetattr(fd, TCSAFLUSH, &oldt);

    return ok ? 0 : -1;
}

static int connect_to_backend(void) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    return sock;
}

int main(void) {
    auth_request_t  req;
    auth_response_t resp;

    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));

    printf("=== Privilege-Separated Login ===\n");
    printf("Username: ");
    fflush(stdout);

    if (fgets(req.username, sizeof(req.username), stdin) == NULL) {
        fprintf(stderr, "Failed to read username.\n");
        return EXIT_FAILURE;
    }
    size_t ulen = strlen(req.username);
    if (ulen > 0 && req.username[ulen - 1] == '\n') req.username[ulen - 1] = '\0';

    if (strlen(req.username) == 0) {
        fprintf(stderr, "Username cannot be empty.\n");
        secure_zero(&req, sizeof(req));
        return EXIT_FAILURE;
    }

    if (read_password_no_echo(req.password, sizeof(req.password)) != 0) {
        fprintf(stderr, "Failed to read password.\n");
        secure_zero(&req, sizeof(req));
        return EXIT_FAILURE;
    }

    int sock = connect_to_backend();
    if (sock < 0) {
        fprintf(stderr, "Could not reach authentication backend.\n");
        secure_zero(&req, sizeof(req));
        return EXIT_FAILURE;
    }

    ssize_t wn = write(sock, &req, sizeof(req));
    if (wn != (ssize_t)sizeof(req)) {
        fprintf(stderr, "Incomplete request sent (%zd/%zu bytes).\n",
                wn, sizeof(req));
        secure_zero(&req, sizeof(req));
        close(sock);
        return EXIT_FAILURE;
    }

    secure_zero(&req, sizeof(req));

    ssize_t rn = read(sock, &resp, sizeof(resp));
    close(sock);

    if (rn != (ssize_t)sizeof(resp)) {
        fprintf(stderr, "Malformed or incomplete response from backend.\n");
        return EXIT_FAILURE;
    }

    if (resp.success) {
        printf("Result: ACCESS GRANTED — %s\n", resp.message);
    } else {
        printf("Result: ACCESS DENIED — %s\n", resp.message);
    }

    secure_zero(&resp, sizeof(resp));
    return resp.success ? EXIT_SUCCESS : EXIT_FAILURE;
}
