package main

import (
	_ "embed"
	"encoding/binary"
	"fmt"
)

//go:embed custom_loader.bin
var customLoaderBin []byte

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
//  3. Stage protocol: announce pid + status=1, spin, then call REAL setArgV0
//     with the original JNIEnv*, then dlopen the payload, then write handle +
//     status=2, then unlinkat the staged copy, then madvise the CoW pages
//     back to file-backed, then return to setArgV0's caller.
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
	STAGE_REGION_SIZE              = 0x40000
	DLOPEN_STAGE_DLOPEN_OFF        = 0xf8
	DLOPEN_STAGE_ORIG_HOOK_OFF     = 0x100
	DLOPEN_STAGE_PAYLOAD_PATH_OFF  = 0x108
	DLOPEN_STAGE_PAYLOAD_PATH_SIZE = 128
	DLOPEN_STAGE_MAILBOX_OFF       = 0x188

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
// addresses it needs and the staged payload path.
func BuildDlopenStageImage(dlopenAddr, origHookAddr uint64, libPath string) ([]byte, error) {
	if len(stageDlopenBin) != DLOPEN_STAGE_SIZE {
		return nil, fmt.Errorf("dlopen stage binary size mismatch: got %d want %d", len(stageDlopenBin), DLOPEN_STAGE_SIZE)
	}
	if len(libPath)+1 > DLOPEN_STAGE_PAYLOAD_PATH_SIZE {
		return nil, fmt.Errorf("payload path too long for dlopen stage: %d > %d", len(libPath), DLOPEN_STAGE_PAYLOAD_PATH_SIZE-1)
	}
	stage := make([]byte, len(stageDlopenBin))
	copy(stage, stageDlopenBin)
	binary.LittleEndian.PutUint64(stage[DLOPEN_STAGE_DLOPEN_OFF:], dlopenAddr)
	binary.LittleEndian.PutUint64(stage[DLOPEN_STAGE_ORIG_HOOK_OFF:], origHookAddr)
	// Zero the path area then copy the staged path (no terminator beyond the buffer).
	for i := range DLOPEN_STAGE_PAYLOAD_PATH_SIZE {
		stage[DLOPEN_STAGE_PAYLOAD_PATH_OFF+i] = 0
	}
	copy(stage[DLOPEN_STAGE_PAYLOAD_PATH_OFF:], []byte(libPath))
	return stage, nil
}

// BuildCustomLoaderShellcode patches the embedded 428-byte stub with the
// zygote pid, target app uid, original setArgV0 address (for the parent path
// + stage call-through), stage file path, and the stage's data-slot offsets.
func BuildCustomLoaderShellcode(zygotePid int, origHookAddr uint64, stagePath string, targetUID int) ([]byte, error) {
	if len(customLoaderBin) != CUSTOM_TRAP_SIZE {
		return nil, fmt.Errorf("custom stub binary size mismatch: got %d want %d", len(customLoaderBin), CUSTOM_TRAP_SIZE)
	}
	if len(stagePath)+1 > STUB_STAGE_PATH_SIZE {
		return nil, fmt.Errorf("stage path too long for stub path slot: %d > %d", len(stagePath), STUB_STAGE_PATH_SIZE-1)
	}
	trap := make([]byte, len(customLoaderBin))
	copy(trap, customLoaderBin)
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
