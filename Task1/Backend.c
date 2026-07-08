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
static int constant_time_equal(const char *a, const char *b, size_t max_len) {
    size_t la = strnlen(a, max_len);
    size_t lb = strnlen(b, max_len);
    unsigned char diff = (unsigned char)(la ^ lb);
    for (size_t i = 0; i < max_len; i++) {
        unsigned char ca = (i < la) ? (unsigned char)a[i] : 0;
        unsigned char cb = (i < lb) ? (unsigned char)b[i] : 0;
        diff |= (unsigned char)(ca ^ cb);
    }
    return diff == 0;
}

static int validate_credentials(const char *username, const char *password) {
    for (size_t i = 0; i < NUM_CREDENTIALS; i++) {
        if (strncmp(username, g_credentials[i].username, MAX_USER_LEN) == 0) {
            return constant_time_equal(password, g_credentials[i].password, MAX_PASS_LEN);
        }
    }
    return 0;
}
static auth_stats_t *setup_shared_memory(void) {
    shm_unlink(SHM_NAME);
    int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR | O_EXCL, 0600);
    if (fd < 0) {
        perror("shm_open");
        return NULL;
    }
    if (ftruncate(fd, sizeof(auth_stats_t)) != 0) {
        perror("ftruncate");
        close(fd);
        shm_unlink(SHM_NAME);
        return NULL;
    }
    void *addr = mmap(NULL, sizeof(auth_stats_t),
                       PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (addr == MAP_FAILED) {
        perror("mmap");
        shm_unlink(SHM_NAME);
        return NULL;
    }
    memset(addr, 0, sizeof(auth_stats_t));
    return (auth_stats_t *)addr;
}
static int drop_privileges_permanently(const char *target_user) {
    struct passwd *pw = getpwnam(target_user);
    if (pw == NULL) {
        fprintf(stderr, "Cannot resolve user '%s'\n", target_user);
        return -1;
    }

    uid_t target_uid = pw->pw_uid;
    gid_t target_gid = pw->pw_gid;

    if (setresgid(target_gid, target_gid, target_gid) != 0) {
        perror("setresgid");
        return -1;
    }

    if (setresuid(target_uid, target_uid, target_uid) != 0) {
        perror("setresuid");
        return -1;
    }

    if (geteuid() != target_uid) {
        fprintf(stderr, "FATAL: privilege drop verification failed "
                        "(geteuid()=%d, expected %d)\n",
                        geteuid(), target_uid);
        return -1;
    }

    if (setuid(0) == 0) {
        fprintf(stderr, "FATAL: root privileges were reclaimable after drop!\n");
        return -1;
    }

    fprintf(stderr, "[backend] Privileges permanently dropped. "
                     "Now running as uid=%d, euid=%d\n", getuid(), geteuid());
    return 0;
}
static void handle_client(int client_fd) {
    auth_request_t req;
    auth_response_t resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));

    struct ucred peer;
    socklen_t len = sizeof(peer);
    if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &peer, &len) == 0) {
        fprintf(stderr, "[backend] Connection from pid=%d uid=%d gid=%d\n",
                peer.pid, peer.uid, peer.gid);
    }

    ssize_t rn = read(client_fd, &req, sizeof(req));
    __atomic_fetch_add(&g_stats->total_attempts, 1, __ATOMIC_SEQ_CST);

    if (rn != (ssize_t)sizeof(req)) {
        fprintf(stderr, "[DEBUG] rn=%zd expected=%zu\n", rn, sizeof(req));
        __atomic_fetch_add(&g_stats->malformed_rejected, 1, __ATOMIC_SEQ_CST);
        resp.success = 0;
        snprintf(resp.message, sizeof(resp.message), "Malformed request");
        write(client_fd, &resp, sizeof(resp));
        secure_zero(&req, sizeof(req));
        return;
    }

    req.username[MAX_USER_LEN - 1] = '\0';
    req.password[MAX_PASS_LEN - 1] = '\0';

    int ok = validate_credentials(req.username, req.password);
    if (ok) {
        __atomic_fetch_add(&g_stats->successful_attempts, 1, __ATOMIC_SEQ_CST);
        resp.success = 1;
        snprintf(resp.message, sizeof(resp.message), "Welcome, %s", req.username);
    } else {
        __atomic_fetch_add(&g_stats->failed_attempts, 1, __ATOMIC_SEQ_CST);
        resp.success = 0;
        snprintf(resp.message, sizeof(resp.message), "Invalid username or password");
    }

    write(client_fd, &resp, sizeof(resp));
    secure_zero(&req, sizeof(req));
    secure_zero(&resp, sizeof(resp));
}

