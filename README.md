# gozinject

A stealthy Android ARM64 process injector. No ptrace, no traces.

## How It Works

1. Traps `android_os_Process_setArgV0` in zygote64 via `/proc/pid/mem`
2. Spawns the target app — the child inherits the trap
3. Child executes shellcode: opens payload, unlinks from disk, calls `dlopen`
4. Mailbox handshake confirms injection, zygote is restored to original state
5. Post-injection: soinfo unlinking, anonymous remap, linker scrub

No ptrace attachment. No debugger. No file left on disk. No trace in maps.

## Injection Modes

| Mode | Flag | Maps Visibility | File on Disk |
|------|------|-----------------|--------------|
| Standard | (none) | Full path visible | Yes |
| Stealth | `-stealth` | `(deleted)` suffix | Briefly, then unlinked |
| Memfd | `-memfd` | `/memfd:jit-cache (deleted)` | Never |

## Features

- **No Ptrace** — evades anti-debug checks that look for `TracerPid != 0`
- **Spawn Mode** — injects at process creation, before anti-tamper initializes
- **Ghost Mode** (`-stealth`) — payload unlinked before dlopen, innocuous staging names
- **Memfd Mode** (`-memfd`) — payload never touches disk, loaded from anonymous memory fd
- **soinfo Unlinking** — removes payload from linker's library list (hides from `dl_iterate_phdr`)
- **Anonymous Remap** — replaces file-backed VMAs with anonymous mappings
- **Linker Scrub** — zeros payload path strings from all writable memory
- **Stripped Binary** — no symbols, no DWARF, no build paths
- **Timing Hardening** — jittered polling to avoid timing fingerprints

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
# Standard injection (visible in maps)
xmake run --pkg=com.target.app --lib=/path/to/payload.so

# Stealth mode (file unlinked, post-injection hiding)
xmake run --pkg=com.target.app --lib=/path/to/payload.so --stealth --debug

# Maximum stealth: memfd (no file ever touches disk)
xmake run --pkg=com.target.app --lib=/path/to/payload.so --memfd --debug

# With logcat streaming
xmake run --pkg=com.target.app --lib=/path/to/payload.so --memfd --logcat
```

## Stealth Layers

| Layer | Technique | Hides From |
|-------|-----------|------------|
| Filesystem | Payload unlinked before dlopen / memfd (never on disk) | File scanners, `stat()` checks |
| Process Maps | Anonymous remap replaces file-backed VMAs | `/proc/self/maps` scanners |
| Linker | soinfo node unlinked from linked list | `dl_iterate_phdr()`, `dladdr()` |
| Memory | All path strings zeroed in writable regions | String-based memory scanners |
| Binary | `-trimpath -ldflags="-s -w"` | Static analysis, `strings` |
| Process Name | Randomized system-like name on device | Process list scanners |
| Timing | Jittered polling, fast-start detection | Timing side-channel analysis |
| Cleanup | Injector + payload removed after execution | Post-mortem forensics |

## Project Structure

```
src/
├── main.go               # CLI, mode selection, payload staging
├── injector.go           # Core injection + post-injection stealth orchestration
├── memfd.go              # memfd_create fileless injection path
├── shellcode_builder.go  # ARM64 shellcode generation (agnostic + memfd variants)
├── soinfo.go             # Linker soinfo linked list parsing and unlinking
├── remap.go              # Anonymous VMA remapping via thread hijack
├── linker_scrub.go       # Path string scrubbing from process memory
├── timing.go             # Jittered polling and timing configuration
├── memory.go             # /proc/pid/mem primitives (read/write/pointer/string)
├── maps.go               # /proc/pid/maps parsing
├── elf.go                # ELF symbol resolution
├── utils.go              # Process discovery, activity resolution
├── stealth.go            # Staging utilities and environment validation
└── logger.go             # Structured logging (catppuccin theme)
```

## Detection Surface (remaining)

After all stealth phases complete successfully:

- **Executable pages exist** that aren't backed by any known file — sophisticated integrity checkers that hash all executable memory against known-good values could detect this
- **Thread timing** — the brief hijack of a blocked thread may be observable via precise timing measurements
- **Behavioral** — whatever the payload does (hooks, network calls, etc.) is still observable at the behavioral level

These are inherent to any in-memory injection technique and cannot be eliminated from the injector side.

## License

Private. Do not distribute.
