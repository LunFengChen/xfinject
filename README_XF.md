# xfinject

`xfinject` is the XF-maintained fork of `Arsylk/gozinject` for reusable Android
SO injection experiments.

Scope of this repository:

- generic Android/arm64 injector CLI (`xfinjectd`);
- generic c-shared wrapper (`libxfinject.so`);
- request/allowlist JSON contract useful for callers that want a stable wrapper;
- no AOSP product wiring, no ROMManager code, no bundled payload such as jnilog.

Build release assets:

```bash
./build-xfinject.sh
```

Outputs:

```text
dist/xfinjectd
dist/libxfinject.so
dist/libxfinject.h
```

AOSP/ROM integration should consume GitHub Release assets from this repository
rather than vendoring this source tree into the ROM patch repository.
