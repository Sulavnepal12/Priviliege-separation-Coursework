#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pwd.h>

#define SOCKET_PATH     "/tmp/authsock_secure"
#define SHM_NAME        "/auth_backend_stats"
#define MAX_USER_LEN    32
#define MAX_PASS_LEN    64
#define BACKLOG         16
#define TARGET_USER     "nobody"

typedef struct {
    char username[MAX_USER_LEN];
    char password[MAX_PASS_LEN];
} auth_request_t;

typedef struct {
    int  success;
    char message[64];
} auth_response_t;

typedef struct {
    unsigned long total_attempts;
    unsigned long successful_attempts;
    unsigned long failed_attempts;
    unsigned long malformed_rejected;
} auth_stats_t;

static auth_stats_t *g_stats = NULL;
static volatile sig_atomic_t g_shutdown = 0;
typedef struct {
    const char *username;
    const char *password;
} credential_t;

static const credential_t g_credentials[] = {
    { "alice", "Str0ngPass!23" },
    { "bob",   "AnotherSecret9" },
};
#define NUM_CREDENTIALS (sizeof(g_credentials) / sizeof(g_credentials[0]))

static void *(*volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_zero(void *buf, size_t len) {
    if (buf != NULL && len > 0) {
        secure_memset_ptr(buf, 0, len);
    }
}

