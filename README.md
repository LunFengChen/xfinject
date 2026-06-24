# xfinject

A stealthy Android ARM64 process injector for authorized security testing. No `ptrace`,
no debugger attach, no persistent fingerprint visible to the injected app.

Validated on Android 16 (API 36), kernel 4.19 with a custom `vma_hide` module, against
an app protected by jiagu packer plus standard anti-tamper checks. End-to-end the
child process exposes **no observable artifact** of injection through `/proc/self/maps`,
`/proc/self/smaps`, the linker's `solist`, byte-level content hashes of patched system
libraries, the on-disk staging directory, or open file descriptors.

---

## Threat model

The adversary runs **inside the target app's UID sandbox** — the classic in-process
anti-tamper / anti-cheat / anti-debug scanner. They can:

- Read their own `/proc/self/maps`, `/proc/self/smaps`, `/proc/self/status`
- Walk the linker's `solist` via `dl_iterate_phdr` / `dlinfo`
- Hash memory regions against on-disk copies of system libraries
- Enumerate their own `/proc/self/fd`
- Inspect files inside their data dir
- Read thread names, signal masks, working directory, environment

They **cannot** read other processes' `/proc/<pid>/*` (SELinux + UID isolation), and
they cannot read kernel ring buffers. The injector binary plus a small kernel hook
operate outside that sandbox.

---

## High-level flow

```
host                                         device (rooted)
────                                         ──────────────
xmake b injector ──push──> /data/local/tmp/app_process_XXXX  (injector binary, root)
xmake run        ──push──> /data/local/tmp/<lib>.so          (payload)

                              ┌─────────────────────────────────────────────┐
                              │  injector (root via su)                     │
                              │                                             │
                              │  1. detect API from /system/build.prop      │
                              │  2. resolve app UID via syscall.Stat        │
                              │  3. clear /proc/vma_hide entries for UID    │
                              │  4. force-stop pkg (skip if already dead),  │
                              │     bounded-poll for kill to take effect    │
                              │  5. stage payload → /data/data/<pkg>/       │
                              │     .org.chromium.<rand>.tmp                │
                              │  6. resolve setArgV0 + __loader_dlopen      │
                              │  7. write 428-byte stub @ setArgV0          │
                              │  8. am start <main_activity>                │
                              │  9. detect new child via /proc walk ──┐     │
                              │ 10. restore zygote setArgV0           │     │
                              │ 11. poll stage mailbox value=1        │  ┌──┴─────────────────┐
                              │ 12. restore child setArgV0            │  │  child app process │
                              │ 13. write release flag (value=1)      ├──┤  • mmap 256K RWX   │
                              │ 14. poll mailbox value>=2 → handle    │  │  • read stage      │
                              │ 15. poll mailbox value=3 (stage ret)  │  │  • BR to stage     │
                              │ 16. UnlinkSoinfo + vma_hide           │  │  • value=1 (ready) │
                              │     (file segs + guards + bss)        │  │  • BLR real        │
                              │ 17. vma_hide stage region             │  │    setArgV0        │
                              │ 18. exit (binary removed by xmake)    │  │  • dlopen()        │
                              └────────────────────────────────────────┘  │  • value=2         │
                                                                          │  • unlinkat .tmp   │
                                                                          │  • madvise CoW     │
                                                                          │  • value=3         │
                                                                          │  • RET             │
                                                                          └────────────────────┘
```

The diagram shows the single-payload essence; with several `--lib` payloads the
stage loads them in order and the injector gates each one (see §3 for the exact
`gate`/`loaded` mailbox handshake). No `ptrace`. No debugger attach. The hook is a
one-shot byte-patch on a single function, restored as soon as the target child is
spotted.

---

## Stealth layers

Each layer closes a specific detection surface. They are layered because no single
technique is sufficient on its own.

### 1. Trap location: `setArgV0`

We trap `_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring` in
`/system/lib64/libandroid_runtime.so`. The Java framework calls this exactly once per
forked app — **after** `fork()` and **before** the app's main code runs — to rename
the process from `<pre-initialized>` to its package name. This is the narrow window
in which the app's anti-tamper has not yet initialized but the process is fully a
child of zygote.

Why not other entry points:
- Trapping a zygote function would corrupt zygote globally on the first trigger.
- Trapping in the linker would be too early (no JNI, no real process identity).
- Trapping in `JNI_OnLoad` of an app library is too late (anti-tamper already armed).

### 2. Stub + stage architecture

The trap itself is only 428 bytes (`custom_stub.s` → `custom_stub.bin`). Its job:

1. Filter — `getpid()` matches zygote, then `getuid()` matches the target app's
   UID, so unrelated forks (`SystemUI`, `system_server` children) fall straight
   through to the real `setArgV0`.
2. `openat`/`mmap` a 256 KB anonymous RWX region, `read` the 4 KB stage file from
   `/data/local/tmp/.gzs.<nanos>` into it.
3. Patch the stage's `_orig_hook_slot` with the address of the real `setArgV0`.
4. `BR` to the stage.

The stub uses only `x16`/`x17` (caller-saved IP scratch) and `x9`–`x11` — never any
callee-saved register. AArch64 callee-saved state (`x19`–`x28`) flows through to
the stage untouched, so the original caller's state is preserved bit-for-bit across
the trap.

This was a real bug we fixed: an earlier revision used `x21`/`x22` as scratch, which
silently corrupted ART's runtime state. The app would keep running and crash later
— "system memory corruption after one launch".

### 3. The dlopen stage

The 4 KB stage (`stage_dlopen.s` → `stage_dlopen.bin`) runs from the new RWX
anonymous mapping — never from a patched system library — so the injector can safely
restore the child's `setArgV0` page without clobbering still-executing shellcode.
This is the fundamental icache problem that makes "inline" traps unsafe across COW
restores.

The stage loads N payloads (passed via repeated `--lib`, in order) into the one
trapped child. The mailbox is a 48-byte struct at a fixed offset in the stage
region, laid out as five `uint64` slots. `gate` (injector → stage) and `loaded`
(stage → injector) are monotonic counters that gate each payload:

| offset | name   | written by | meaning                                              |
|--------|--------|------------|------------------------------------------------------|
| `0x00` | handle | stage      | dlopen return value for the payload currently loading |
| `0x08` | pid    | stage      | child's getpid (for cross-check / self-identification) |
| `0x10` | status | stage      | `1` = announced & spinning, `3` = stage done (about to RET) |
| `0x18` | gate   | injector   | `1` releases the single `setArgV0`; `i+2` acks payload `i` |
| `0x20` | loaded | stage      | `i+1` published once payload `i`'s dlopen has returned |

Sequence inside the stage:

1. Save the full AArch64 callee-saved set + caller's `x0..x3, x8, x29, x30`.
2. Write `pid` + `status=1` into the mailbox, then spin until `gate >= 1`.
3. Injector observes `status=1`, restores the child's `setArgV0` page, writes
   `gate=1`. Stage breaks the spin.
4. Restore caller args, `BLR` the real `setArgV0` **once** (original bytes are
   back now).
5. For each payload `i` in `0..N-1`:
   a. `__loader_dlopen(path[i], RTLD_NOW, NULL)` (null caller-addr selects the
      default namespace); write the `handle`.
   b. `unlinkat(AT_FDCWD, path[i], 0)` — delete the staged copy from disk. The
      kernel keeps the inode alive through the now-mapped segments.
   c. Write `loaded=i+1`, then spin until `gate >= i+2` (the injector's ack).
6. `madvise(page_align(setArgV0), 8192, MADV_DONTNEED)` — drop the two CoW'd pages
   of `libandroid_runtime.so` `.text`. The kernel reverts them to file-backed, so
   smaps `Anonymous` and `Private_Dirty` go back to zero. Works on any kernel since
   2.4 (we target 4.19, pre-`process_madvise`).
7. Write `status=3` ("stage done, about to RET") — the handshake the injector waits
   for before hiding the stage region — then restore all registers and `RET` to the
   original `setArgV0` call site. The stage page is no longer executing after this.

The injector side mirrors the loop: it releases `gate=1`, then for each payload
waits for `loaded >= i+1`, records the handle, and acks `gate=i+2`. The
handle slot stays stable between those two because the stage blocks on the ack
before overwriting it. The soinfo-unlink + VMA-hide teardown (§5) is deferred until
**after** every payload is loaded — unlinking a soinfo that is the linker's solist
tail would dangle the linker's tail pointer and orphan the next payload's node.

### 4. CoW-page restoration to byte-identity

Writing the trap to zygote's `setArgV0` triggers Copy-on-Write: the kernel allocates
an anonymous private page, copies the file-backed bytes, applies the trap. Writing
the original bytes back into that page **content-restores** but **not page-restores**
— the page is still anonymous, not file-backed.

Two-step fix:

- **In zygote**: irrelevant. `/proc/zygote/smaps` is gated by SELinux
  (`u:r:zygote:s0`); apps can never read it.
- **In the child**: `madvise(page, 8192, MADV_DONTNEED)` from the stage drops the
  anonymous page; subsequent access faults back from the page cache. Net result:
  smaps `Anonymous=0`, `Private_Dirty=0`, `Shared_Clean=full segment size`. SHA-256
  of the 428-byte trap window matches the disk file byte-for-byte.

### 5. soinfo unlinking

After `dlopen` succeeds, the payload is on the linker's `__dl__ZL6solist` linked
list. `dl_iterate_phdr` walks this list and would expose the payload to any caller.
We:

1. Read the head pointer from `__dl__ZL6solist` (resolved via prefix match to handle
   LLVM hash suffixes like `.llvm.3423636157476772985`).
2. Walk forward via the `next` pointer (offset is stable at `0x28` across API levels).
3. Match on the `realpath` field (libc++ `std::string` SSO; the walker probes a
   small window of candidate offsets and accepts only `/`-prefixed decodes, so AOSP
   struct drift across API levels is absorbed automatically).
4. Patch the previous node's `next` to skip ours, or update the head if we're first.

After unlink, `dl_iterate_phdr` yields no entry for the payload.

### 6. `/proc/maps` hiding via per-UID `vma_hide`

This needs a custom kernel module exposing `/proc/vma_hide` with a per-UID hide list.
It is **optional**: `--vma-hide` selects `auto` (the default — use the module iff
`/proc/vma_hide` exists), `always` (use it; warn, don't abort, if writes fail), or
`never` (skip it entirely). When inactive, the payload's VMAs are simply left visible
in `/proc/<pid>/maps`; everything else — soinfo unlinking, on-disk cleanup, CoW
restoration — is independent of the module and still runs. Write commands:

```
clear           # global wipe (all UIDs)
clear <uid>     # wipe only this UID's entries — used at injection start
add <uid> 0xSTART 0xEND   # per-UID hide, repeated per VMA
```

The kernel hook filters listed VMAs out of `/proc/<pid>/maps` and `/proc/<pid>/smaps`
**only for readers whose `current_uid()` matches the entry's `<uid>`** — root (uid 0)
always bypasses the filter. The pages stay mapped; only enumeration is filtered.

The injector adds entries for:

- **3 payload PT_LOAD segments** (`r-xp`, `r--p`, `rw-p`) — file-backed, named by the
  staged `.tmp` path.
- **Bionic guard pages** (`---p`, anonymous) touching a payload boundary. These are
  remnants of the linker's initial PROT_NONE reservation and reveal the segment-gap
  alignment of a typical `.so` even when the file-backed regions are gone.
- **`[anon:.bss]`** (`rw-p`, named) immediately after the last payload segment. Sized
  to `LOAD#3 (memsz − filesz)`, this is the zero-init tail of the payload's data
  segment and was the most distinctive of the leftover signals.
- **The 256 KB stage region** (`rwxp`, anonymous). The stub `mmap`s exactly `0x40000`
  bytes for the stage; this exact-size RWX anonymous mapping outside ART's code-cache
  pattern was an obvious fingerprint until we hid it.

Detection of satellite VMAs is fixed-point: each newly-added region extends the
boundary set, so a chain `r-xp ↔ ---p ↔ r--p ↔ ---p ↔ rw-p ↔ [anon:.bss]` is fully
absorbed in one pass.

### 7. List-cleanup at injection start

`/proc/vma_hide`'s list is kernel-global state. Stale entries from a previous run
into the same app can linger and (on the older global-list kernel) shadow the new
stage's address. We `clear <uid>` at the **first** action in `RunInjector`. With the
per-UID kernel module this is correctness-optional — the injector reads as root
and is never filtered — but tidy across multiple injections into the same app.

### 8. Filesystem cleanup

The staged payload is copied to `/data/data/<pkg>/.org.chromium.<rand>.tmp`. After
`dlopen` succeeds, the **stage** calls `unlinkat` from inside the child process — so
the unlink syscall looks like normal app file activity, not a privileged operation.
The file descriptor is released; the kernel keeps the inode alive via the still-mmap'd
payload segments. **The user's `--lib` source is never referenced by the stage.**

### 9. Injector-binary hygiene

`xmake b injector` builds with `-trimpath -ldflags="-s -w"`: no symbol table, no
DWARF, no host build paths. `xmake run` pushes to `/data/local/tmp/app_process_XXXX`
(random suffix mimicking the canonical `app_process64` naming) and `rm -f`s it after
the run.

---

## Project layout

```
src/
├── main.go               CLI, app force-stop, payload staging, hand-off to injector
├── injector.go           Core orchestration: trap install/restore, child detection,
│                         mailbox wait, dlopen handshake, post-injection stealth
├── shellcode_builder.go  Embeds .bin files, patches stub/stage data slots, defines
│                         the data-slot layout constants
├── soinfo.go             Linker solist walker, soinfo unlink, /proc/vma_hide
│                         interface (per-UID), satellite-VMA discovery (guards + bss)
├── memory.go             /proc/<pid>/mem primitives (read/write/pointer/string)
├── maps.go               /proc/<pid>/maps parser
├── elf.go                ELF symbol resolution (file + via maps base)
├── utils.go              Process discovery, activity resolution, force-stop, uid
│                         lookup (syscall.Stat — no exec), API-level detection
├── logger.go             Structured logging (catppuccin theme, per-key colors)
├── custom_stub.bin       428-byte stub binary (embed)
└── stage_dlopen.bin      4 KB stage binary (embed)

custom_stub.s             stub source — assemble with aarch64-linux-gnu-as
stage_dlopen.s            stage source — assemble with aarch64-linux-gnu-as
xmake.lua                 build + deploy + run task definition
```

The `.bin` blobs are checked in (they are `//go:embed`-ed), but they can no longer
silently drift from the `.s` sources: `xmake b injector` reassembles each `.s` and
**fails the build** if it no longer matches the committed `.bin`. After editing a
source, regenerate the binaries with:

```bash
xmake stubgen            # reassembles custom_stub.s / stage_dlopen.s → src/*.bin
```

(The guard and `stubgen` need `binutils-aarch64-linux-gnu`; without it the guard
is skipped so a Go-only environment still builds, and CI with binutils enforces
it.) If you change offsets, also update the `STUB_*_OFF` / `DLOPEN_STAGE_*_OFF`
constants in `shellcode_builder.go` to match the new disassembly.

---

## Prerequisites

- Rooted Android device (Magisk / KernelSU / similar) — `su -c` must work
- Custom kernel with a `vma_hide` module exposing `/proc/vma_hide` with the per-UID
  ABI: `add <uid> 0x<s> 0x<e>` / `clear <uid>` / `clear`
- SELinux permissive **or** an appropriate policy allowing root to write
  `/proc/<pid>/mem` for system processes
- Go ≥ 1.23 and xmake on the build host
- `aarch64-linux-gnu-binutils` on the host if you intend to rebuild the `.bin` files

---

## Build

```bash
xmake b injector       # → dist/injector  (android/arm64, stripped, no CGo)
```

## Usage

```bash
# Inject libfoo.so into com.example.app
xmake run --pkg=com.example.app --lib=/path/to/libfoo.so

# Inject several payloads, in the given order (comma-separated)
xmake run --pkg=com.example.app --lib=/path/to/libfoo.so,/path/to/libbar.so

# With debug logs
xmake run --pkg=com.example.app --lib=/path/to/libfoo.so --debug

# Stream the injected child's logcat after dlopen (Ctrl-C, or the child exiting,
# stops the stream and tears the app down with it)
xmake run --pkg=com.example.app --lib=/path/to/libfoo.so --logcat

# Stream only specific tags, raw format (implies --logcat). Repeat --logtag to
# whitelist more than one tag (exact-tag filterspec, not regex)
xmake run --pkg=com.example.app --lib=/path/to/libfoo.so --logtag=MyTag --logtag=OtherTag

# Control the /proc/vma_hide kernel module: auto (default; use it iff present) |
# always | never
xmake run --pkg=com.example.app --lib=/path/to/libfoo.so --vma-hide=never

# Optional post-dlopen autostart hook. The stage calls dlsym(handle, symbol)
# and invokes int (*)(const char*) with the supplied argument before unlinking
# the staged payload. This is generic; xfQTrace uses it to call
# xfqtrace_configure_file_and_start_async(config_path).
/data/local/tmp/xfinjectd -pkg com.example.app -lib /data/local/tmp/libxfqtrace.so \
  -autostart-symbol xfqtrace_configure_file_and_start_async \
  -autostart-arg /data/data/com.example.app/cache/xfqtrace_config.json

# Request JSON callers can pass the same autostart fields:
#   "autostart_symbol": "xfqtrace_configure_file_and_start_async",
#   "autostart_arg": "/data/data/.../cache/xfqtrace_config.json"

# Specific device
xmake run -s <serial> --pkg=com.example.app --lib=/path/to/libfoo.so
```

The xmake task pushes injector + payload(s) to `/data/local/tmp`, runs the injector
under `su`, then removes the files. The injector itself handles the rest. The
underlying binary takes a repeatable `-lib` (one per payload); the xmake task
accepts them comma-separated and expands them.

### Sample output (info level)

```
[+] injector start package=com.example.app payloads=2
[+] vma_hide mode=auto active=true
[+] zygote located zygote_pid=1012
[+] resolved activity package=com.example.app activity=com.example.app/.MainActivity
[+] stage injector start package=com.example.app api=36
[+] install trap addr=0x7f0b804f18 size=428
[+] waiting for stage package=com.example.app zygote_pid=1012 mailbox_off=0x178 timeout_ms=20000
[+] stage ready child_pid=23761 mailbox=0x7f1840d140 value=0x1
[+] dlopen complete index=0 payload=/data/data/com.example.app/.org.chromium.8f41c3132b9d3df9.tmp handle=0x52bdfee21f1aa963
[+] dlopen complete index=1 payload=/data/data/com.example.app/.org.chromium.1b7c0a9e44d5e210.tmp handle=0x10ca5b8930a6eff7
[+] payload vmas hidden count=5 base=0x7be16f4000 end=0x7be2581000
[+] soinfo unlinked path=/data/data/com.example.app/.org.chromium.8f41c3132b9d3df9.tmp
[+] payload vmas hidden count=5 base=0x7be25a0000 end=0x7be25a9000
[+] soinfo unlinked path=/data/data/com.example.app/.org.chromium.1b7c0a9e44d5e210.tmp
[+] stage vma hidden stage_base=0x7f1840d000 stage_end=0x7f1844d000
[+] cloaked child_pid=23761 payloads=2 uid=10511 elapsed_ms=249
```

The trace bookends with `injector start` and `cloaked`; every line in between is
either a milestone (trap installed, child located, dlopen returned per payload) or
a confirmed hide operation. No magic-number waits remain — every "waiting" is a
bounded poll on an observable state transition.

## Verification

Quick check that the payload is loaded but invisible:

```bash
PID=$(adb shell "su -c 'pidof com.example.app'" | tr -d '\r\n')

# Per-UID hide list — 8 entries (3 segments + 3 guards + 1 bss + 1 stage)
adb shell "su -c 'cat /proc/vma_hide'"

# libandroid_runtime.so r-xp should be pristine
adb shell "su -c 'awk \"/libandroid_runtime/&& / r-xp /{p=1} p&&/^Anon|^Private_Dirty/\" /proc/$PID/smaps'"

# Full r-xp segment hashes identically to disk
RX=$(adb shell "su -c \"awk '/libandroid_runtime/ && / r-xp /{print \\\$1, \\\$3; exit}' /proc/$PID/maps\"")
# (manual check; addresses depend on the run)
```

Note that root reads bypass the hide filter by design — to confirm the app is truly
blind, inspect from a same-UID context (an installed helper running as the app's UID
in its SELinux domain) or trust the kernel module's documented contract.

---

## What this does NOT hide

Intentional residuals worth knowing about:

- **Zygote's `libandroid_runtime.so` `.text`** still has 8 KB anonymous CoW after
  the trap/restore cycle in zygote. Not reachable from app UIDs (SELinux). To clean
  zygote too you'd extend the kernel module with a "do_madvise from kernel context"
  command and call it on zygote's pid; we judged the added complexity unjustified
  given the threat model.
- **Behavioral signals** from whatever the payload itself does (network calls, hooks
  it installs, files it writes). The injector can't help here — that's payload
  hygiene.
- **Page-cache thermal**: the staged `.tmp` file briefly existed on disk before
  `unlinkat`. Filesystem journaling could theoretically retain a trace. Not
  observable from a sandboxed app.

---

## License

[MIT](LICENSE) © 2026 Arsylk.

The injector is provided strictly for authorized security research, red-team
exercises with documented permission, and educational use. Running it against
processes you don't own or aren't explicitly authorized to test is your
responsibility, not ours.
