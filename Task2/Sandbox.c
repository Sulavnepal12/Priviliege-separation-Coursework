#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <pthread.h>
#include <stdatomic.h>

#define TIMEOUT_SEC 10
#define LOG_FILE "logs/sandbox_log.txt"
#define MEM_LIMIT_KB (50*1024)
#define CPU_LIMIT_SEC 3

static volatile sig_atomic_t g_timed_out = 0;
static pid_t g_child_pid = -1;
static atomic_bool g_child_alive;
static void alarm_handler(int sig) {
    (void)sig;
    g_timed_out = 1;
    if (g_child_pid > 0) kill(g_child_pid, SIGTERM);
}
static void *monitor_fn(void *arg) {
    (void)arg;
    struct rusage u;
    while (atomic_load(&g_child_alive)) {
        getrusage(RUSAGE_CHILDREN, &u);
        double cpu = u.ru_utime.tv_sec + u.ru_stime.tv_sec;
        if (u.ru_maxrss > MEM_LIMIT_KB) {
            fprintf(stderr, "[sandbox] MEMORY LIMIT EXCEEDED (%ld KB)\n", u.ru_maxrss);
            kill(g_child_pid, SIGKILL);
        }
        if (cpu > CPU_LIMIT_SEC) {
            fprintf(stderr, "[sandbox] CPU LIMIT EXCEEDED (%.0fs)\n", cpu);
            kill(g_child_pid, SIGKILL);
        }
        usleep(100000);
    }
    return NULL;
}
