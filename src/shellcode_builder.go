package main

import (
	_ "embed"
	"encoding/binary"
	"fmt"
)

//go:embed custom_stub.bin
var customStubBin []byte

//go:embed stage_dlopen.bin
var stageDlopenBin []byte

// Stub + dlopen-stage protocol.
//
//  1. custom_stub (428 bytes) is patched at zygote's setArgV0. It checks pid
//     (zygote-passthrough) and uid (only the target app proceeds), then mmaps
//     a 256 KB anonymous RWX region, reads the stage file into it, fixes up
//     the stage's data slots, and branches to the stage.
//  2. stage_dlopen runs from that anonymous RWX page — completely outside
//     libandroid_runtime — so the injector can safely restore the child's
//     setArgV0 page without clobbering still-executing shellcode.
//  3. Stage protocol: announce pid + status=1, spin until gate>=1, call REAL
//     setArgV0 once with the original JNIEnv*, then for each payload in order:
//     dlopen it, publish the handle, unlinkat the staged copy, publish
//     loaded=i+1, and spin until the injector acks gate>=i+2. After the last
//     one: madvise the CoW pages back to file-backed, status=3, return to
//     setArgV0's caller. See stage_dlopen.s for the full mailbox layout.
//
// Offsets below mirror the labels in custom_stub.s / stage_dlopen.s. If you
// edit either source, reassemble the .bin and update the constants from
// `objdump -D` of the new bin.
const (
	CUSTOM_PID_PATCH_OFF = 0x20
	CUSTOM_TRAP_SIZE     = 428

	STUB_TARGET_UID_OFF          = 0x114
	STUB_ORIG_HOOK_OFF           = 0x11c
	STUB_STAGE_DATA_OFF_OFF      = 0x124
	STUB_STAGE_DATA_SLOT_OFF_OFF = 0x12c
	STUB_STAGE_ORIG_SLOT_OFF_OFF = 0x134
	STUB_STAGE_PATH_OFF          = 0x13c
	STUB_STAGE_PATH_SIZE         = 96

	// DLOPEN_STAGE_SIZE is the size of the bin file embedded into the stage
	// image. The stub mmaps a much larger region (STAGE_REGION_SIZE) at runtime
	// and reads the bin into the start of it.
	DLOPEN_STAGE_SIZE = 4096
	// STAGE_REGION_SIZE is the size of the anonymous RWX region the stub
	// allocates. Matches `mov x1, #262144` in custom_stub.s. The injector hides
	// this VMA via /proc/vma_hide after the stage has finished executing.
	STAGE_REGION_SIZE = 0x40000
	// Stage data-slot offsets — mirror the labels in stage_dlopen.s. Re-read
	// these from `aarch64-linux-gnu-nm -n stage.o` whenever the stage source
	// changes, since editing the code shifts every slot below it.
	DLOPEN_STAGE_DLOPEN_OFF        = 0x128
	DLOPEN_STAGE_ORIG_HOOK_OFF     = 0x130
	DLOPEN_STAGE_COUNT_OFF         = 0x138
	DLOPEN_STAGE_MAILBOX_OFF       = 0x140
	DLOPEN_STAGE_MAILBOX_SIZE      = 48
	DLOPEN_STAGE_PAYLOAD_PATHS_OFF = 0x170
	DLOPEN_STAGE_PAYLOAD_PATH_SIZE = 128
	// DLOPEN_STAGE_MAX_PAYLOADS is the number of 128-byte path slots reserved in
	// _payload_paths (`.space 128 * 16`). Keep in sync with stage_dlopen.s.
	DLOPEN_STAGE_MAX_PAYLOADS = 16

	// STAGE_DATA_EMBED_OFF / STAGE_DATA_TABLE_SLOT_OFF / STAGE_ORIG_HOOK_SLOT_OFF
	// are referenced by the stub to patch the stage's data table. The dlopen
	// stage doesn't have a per-payload data table, so the stub still writes
	// the two unused slots — point them at the zero-padded tail of the 4 KB
	// stage so they don't clobber any live data or code.
	STAGE_DATA_TABLE_SLOT_OFF = 0xff0
	STAGE_ORIG_HOOK_SLOT_OFF  = DLOPEN_STAGE_ORIG_HOOK_OFF
	STAGE_DATA_EMBED_OFF      = 0xff8
)

// BuildDlopenStageImage patches the embedded 4 KB stage with the runtime
// addresses it needs and the staged payload paths. The stage loads libPaths in
// order, gating each one through the mailbox; libPaths[0] is loaded first.
func BuildDlopenStageImage(dlopenAddr, origHookAddr uint64, libPaths []string) ([]byte, error) {
	if len(stageDlopenBin) != DLOPEN_STAGE_SIZE {
		return nil, fmt.Errorf("dlopen stage binary size mismatch: got %d want %d", len(stageDlopenBin), DLOPEN_STAGE_SIZE)
	}
	if len(libPaths) == 0 {
		return nil, fmt.Errorf("no payload paths supplied to dlopen stage")
	}
	if len(libPaths) > DLOPEN_STAGE_MAX_PAYLOADS {
		return nil, fmt.Errorf("too many payloads for dlopen stage: %d > %d", len(libPaths), DLOPEN_STAGE_MAX_PAYLOADS)
	}
	stage := make([]byte, len(stageDlopenBin))
	copy(stage, stageDlopenBin)
	binary.LittleEndian.PutUint64(stage[DLOPEN_STAGE_DLOPEN_OFF:], dlopenAddr)
	binary.LittleEndian.PutUint64(stage[DLOPEN_STAGE_ORIG_HOOK_OFF:], origHookAddr)
	binary.LittleEndian.PutUint64(stage[DLOPEN_STAGE_COUNT_OFF:], uint64(len(libPaths)))
	// Lay out one NUL-padded path per fixed-size slot; the stage indexes them as
	// _payload_paths + i*DLOPEN_STAGE_PAYLOAD_PATH_SIZE. The slots are already
	// zero from the embedded bin, so only the used bytes need copying.
	for i, libPath := range libPaths {
		if len(libPath)+1 > DLOPEN_STAGE_PAYLOAD_PATH_SIZE {
			return nil, fmt.Errorf("payload path %d too long for dlopen stage: %d > %d", i, len(libPath), DLOPEN_STAGE_PAYLOAD_PATH_SIZE-1)
		}
		off := DLOPEN_STAGE_PAYLOAD_PATHS_OFF + i*DLOPEN_STAGE_PAYLOAD_PATH_SIZE
		copy(stage[off:], []byte(libPath))
	}
	return stage, nil
}

// BuildStubShellcode patches the embedded 428-byte stub with the zygote pid,
// target app uid, original setArgV0 address (for the parent path + stage
// call-through), stage file path, and the stage's data-slot offsets.
func BuildStubShellcode(zygotePid int, origHookAddr uint64, stagePath string, targetUID int) ([]byte, error) {
	if len(customStubBin) != CUSTOM_TRAP_SIZE {
		return nil, fmt.Errorf("custom stub binary size mismatch: got %d want %d", len(customStubBin), CUSTOM_TRAP_SIZE)
	}
	if len(stagePath)+1 > STUB_STAGE_PATH_SIZE {
		return nil, fmt.Errorf("stage path too long for stub path slot: %d > %d", len(stagePath), STUB_STAGE_PATH_SIZE-1)
	}
	trap := make([]byte, len(customStubBin))
	copy(trap, customStubBin)
	binary.LittleEndian.PutUint32(trap[CUSTOM_PID_PATCH_OFF:], 0x52800001|(uint32(zygotePid&0xffff)<<5))
	binary.LittleEndian.PutUint32(trap[STUB_TARGET_UID_OFF:], uint32(targetUID))
	binary.LittleEndian.PutUint64(trap[STUB_ORIG_HOOK_OFF:], origHookAddr)
	binary.LittleEndian.PutUint64(trap[STUB_STAGE_DATA_OFF_OFF:], STAGE_DATA_EMBED_OFF)
	binary.LittleEndian.PutUint64(trap[STUB_STAGE_DATA_SLOT_OFF_OFF:], STAGE_DATA_TABLE_SLOT_OFF)
	binary.LittleEndian.PutUint64(trap[STUB_STAGE_ORIG_SLOT_OFF_OFF:], STAGE_ORIG_HOOK_SLOT_OFF)
	for i := range STUB_STAGE_PATH_SIZE {
		trap[STUB_STAGE_PATH_OFF+i] = 0
	}
	copy(trap[STUB_STAGE_PATH_OFF:], []byte(stagePath))
	return trap, nil
}
