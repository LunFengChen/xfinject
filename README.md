# gozinject

A stealthy Android ARM64 process injector. No ptrace, no traces.

## How It Works

1. Traps `android_os_Process_setArgV0` in zygote64 via `/proc/pid/mem`
2. Spawns the target app — the child inherits the trap
3. Child executes shellcode: opens payload, unlinks from disk, calls `dlopen`
4. Mailbox handshake confirms injection, zygote is restored to original state

No ptrace attachment. No debugger. No file left on disk (stealth mode).

## Features

- **No Ptrace** — evades anti-debug checks that look for `TracerPid != 0`
- **Spawn Mode** — injects at process creation, before anti-tamper initializes
- **Ghost Mode** (`-stealth`) — payload is unlinked before dlopen, staged with innocuous names, injector binary cleaned up after use
- **Stripped Binary** — no symbols, no DWARF, no build paths in the output
- **Randomized Deployment** — injector pushed with system-like process names

## Prerequisites

- Rooted Android device (Magisk, KernelSU, etc.)
- SELinux permissive or appropriate policy
- Go 1.23+ and xmake installed on build machine

## Build

```bash
xmake b injector
```

Produces `dist/injector` (android/arm64, statically linked, stripped).

## Usage

```bash
# Basic injection
xmake run --pkg=com.target.app --lib=/path/to/payload.so

# Stealth mode (recommended)
xmake run --pkg=com.target.app --lib=/path/to/payload.so --stealth --debug

# With logcat streaming
xmake run --pkg=com.target.app --lib=/path/to/payload.so --stealth --logcat
```

## Stealth Measures

| Layer | Technique |
|-------|-----------|
| Filesystem | Payload unlinked before dlopen; staged as `.overlay_<hex>.odex` in app's code_cache |
| Process | Injector binary uses randomized system-like name on device |
| Binary | Built with `-trimpath -ldflags="-s -w"` — no symbols or paths |
| Memory | No ptrace attachment; uses `/proc/pid/mem` directly |
| Timing | Injection happens during `setArgV0` — before `Application.onCreate()` |
| Cleanup | Injector and staged payload removed from device after execution |

## Detection Surface (known limitations)

- `/proc/self/maps` will show the loaded .so with `(deleted)` suffix
- `dl_iterate_phdr` will enumerate the loaded library
- Linker's `soinfo` linked list contains the library entry

These can be addressed with post-injection memory patching (soinfo unlinking, anonymous remap). See source comments for implementation notes.

## Project Structure

```
src/
├── main.go               # CLI entry point, stealth staging
├── injector.go           # Core injection orchestration
├── shellcode_builder.go  # ARM64 shellcode generation
├── memory.go             # /proc/pid/mem read/write
├── maps.go              # /proc/pid/maps parsing
├── elf.go               # ELF symbol resolution
├── utils.go             # Process discovery, activity resolution
├── stealth.go           # Stealth utilities and environment validation
└── logger.go            # Structured logging (catppuccin theme)
```

## License

Private. Do not distribute.
