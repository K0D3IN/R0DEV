/* forcekill - static binary to bypass rootkit kill hook */
#include <unistd.h>
#include <signal.h>

static long sys_kill(long pid, long sig) {
    long ret;
    register long r10 asm("r10") = 0;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(62), "D"(pid), "S"(sig), "d"(r10) : "rcx", "r11", "memory");
    return ret;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    for (int i = 1; i < argc; i++) {
        int pid = 0;
        for (char *p = argv[i]; *p; p++)
            pid = pid * 10 + (*p - '0');
        if (pid > 0) sys_kill(pid, SIGKILL);
    }
    return 0;
}
