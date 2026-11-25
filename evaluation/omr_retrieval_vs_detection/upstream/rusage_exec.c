// rusage_exec CMD [ARGS...]: runs CMD, then prints one line to stderr:
//   RUSAGE wall_s=<s> user_s=<s> sys_s=<s> maxrss_kb=<kB> exit=<code>
// covering CMD and all threads it ran. Used because the upstream demo is one process that plays
// every role and prints only wall-clock stage times.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: rusage_exec CMD [ARGS...]\n");
        return 2;
    }
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        execvp(argv[1], argv + 1);
        perror("execvp");
        _exit(127);
    }
    int status = 0;
    struct rusage ru;
    if (wait4(pid, &status, 0, &ru) < 0) {
        perror("wait4");
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double wall = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) * 1e-9;
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    fprintf(stderr, "RUSAGE wall_s=%.3f user_s=%.3f sys_s=%.3f maxrss_kb=%ld exit=%d\n", wall,
            (double)ru.ru_utime.tv_sec + (double)ru.ru_utime.tv_usec * 1e-6,
            (double)ru.ru_stime.tv_sec + (double)ru.ru_stime.tv_usec * 1e-6, ru.ru_maxrss, code);
    return code;
}
