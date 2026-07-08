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

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program> [args]\n", argv[0]);
        return EXIT_FAILURE;
    }

    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return EXIT_FAILURE; }

    if (pid == 0) {
        execve(argv[1], &argv[1], NULL);
        perror("execve");
        _exit(127);
    }

    g_child_pid = pid;
    atomic_init(&g_child_alive, true);

    pthread_t tid;
    pthread_create(&tid, NULL, monitor_fn, NULL);

    struct sigaction sa = {0};
    sa.sa_handler = alarm_handler;
    sigaction(SIGALRM, &sa, NULL);
    alarm(TIMEOUT_SEC);

    int status = 0;
    waitpid(pid, &status, 0);

    alarm(0);
    atomic_store(&g_child_alive, false);
    pthread_join(tid, NULL);

    if (g_timed_out) {
        usleep(200000);
        if (waitpid(pid, &status, WNOHANG) == 0) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
        }
        fprintf(stderr, "[sandbox] Timeout exceeded, killed.\n");
    }

    clock_gettime(CLOCK_MONOTONIC, &t2);
    double wall = (t2.tv_sec - t1.tv_sec) + (t2.tv_nsec - t1.tv_nsec) / 1e9;

    struct rusage r;
    getrusage(RUSAGE_CHILDREN, &r);
    double user = r.ru_utime.tv_sec + r.ru_utime.tv_usec / 1e6;
    double sys  = r.ru_stime.tv_sec + r.ru_stime.tv_usec / 1e6;

    printf("[sandbox] Target   : %s\n", argv[1]);
    printf("[sandbox] Wall time: %.3f s\n", wall);
    printf("[sandbox] User CPU : %.3f s\n", user);
    printf("[sandbox] Sys time : %.3f s\n", sys);
    printf("[sandbox] Max RSS  : %ld KB\n", r.ru_maxrss);

    if (g_timed_out) printf("[sandbox] Result   : TIMEOUT\n");
    else if (WIFEXITED(status)) printf("[sandbox] Result   : exited, code=%d\n", WEXITSTATUS(status));
    else if (WIFSIGNALED(status)) printf("[sandbox] Result   : killed by signal %d\n", WTERMSIG(status));

    FILE *log = fopen(LOG_FILE, "a");
    if (log) {
        time_t now = time(NULL);
        fprintf(log, "%s | target=%s wall=%.3f user=%.3f sys=%.3f rss=%ld timeout=%d\n",
                ctime(&now), argv[1], wall, user, sys, r.ru_maxrss, g_timed_out);
        fclose(log);
    }

    return 0;
}
