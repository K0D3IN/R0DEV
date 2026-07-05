#include <stdio.h>
#include <string.h>

static long sc(long n, long a1, long a2, long a3) {
    long r;
    register long r10 asm("r10") = a3;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a1), "S"(a2), "d"(r10) : "rcx", "r11", "memory");
    return r;
}

static void kill_all(const char *match) {
    for (int pid = 0; pid < 32768; pid++) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        int fd = sc(2, (long)path, 0, 0); if (fd < 0) continue;
        char buf[256] = {0}; sc(0, fd, (long)buf, 256); sc(3, fd, 0, 0);
        if (strstr(buf, match)) sc(62, pid, 9, 0);
    }
}

static void write_f(const char *path, const char *data) {
    int fd = sc(2, (long)path, 577, 0644);
    if (fd > 0) { sc(1, fd, (long)data, strlen(data)); sc(3, fd, 0, 0); }
}

static void rm(const char *path) { sc(87, (long)path, 0, 0); }
static void rmdir_p(const char *path) { sc(84, (long)path, 0, 0); }
static void exec(const char *f, const char *a1, const char *a2, const char *a3) {
    const char *argv[5] = {f, a1, a2, a3, NULL};
    sc(59, (long)f, (long)argv, 0);
}

int main() {
    kill_all("R0Dev");

    rm("/lib/x86_64-linux-gnu/security.so");
    rm("/opt/R0DEV/rootkit.so"); rm("/opt/R0DEV/loader.sh");
    rm("/opt/R0DEV/fix_rootkit");
    rm("/opt/R0DEV/R0DEV_controle.service");
    rmdir_p("/opt/R0DEV");

    write_f("/etc/ld.so.preload", "");

    exec("/bin/systemctl", "stop", "R0DEV_controle.service", NULL);
    exec("/bin/systemctl", "disable", "R0DEV_controle.service", NULL);
    rm("/etc/systemd/system/R0DEV_controle.service");
    exec("/bin/systemctl", "daemon-reload", NULL, NULL);

    write_f("/proc/sys/vm/drop_caches", "3");
    return 0;
}
