package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	childWaitTimeout  = 10 * time.Second
	stageWaitTimeout  = 10 * time.Second
	dlopenWaitTimeout = 10 * time.Second
	stageDoneTimeout  = 1 * time.Second
	childPollInterval = 5 * time.Millisecond
	stagePollInterval = 2 * time.Millisecond
)

func processCmdlineContains(pid int, match string) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return bytes.Contains(data, []byte(match))
}

func uint64Bytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// RunInjector orchestrates the stub-and-stage injection:
//   - patches a 428-byte stub at zygote's setArgV0;
//   - on the first matching fork, the stub mmaps the stage from a file and
//     branches to it;
//   - the stage announces itself via a mailbox at a fixed offset inside its
//     own anonymous RWX mapping, then spins;
//   - the injector restores the child's setArgV0 page, releases the spin,
//     waits for status=2 + dlopen handle, then unlinks the payload soinfo
//     and hides its VMA ranges (plus the stage region) via /proc/vma_hide.
//
// apiLevel selects the right soinfo struct offsets for the running Android
// version (resolved at startup via getprop ro.build.version.sdk).
func RunInjector(pkgName, libPath string, zygotePid int, mainActivity string, apiLevel int) (int, error) {
	startedAt := time.Now()
	logger.Info("stage injector start", "package", pkgName, "api", apiLevel)

	targetUID := GetAppUID(pkgName)
	if targetUID <= 0 {
		return 0, fmt.Errorf("resolve uid for %s", pkgName)
	}
	logger.Debug("resolved app uid", "package", pkgName, "uid", targetUID)

	// Clear any stale per-UID entries from a previous injection into this app.
	// Correctness-optional with the per-UID kernel module (root reads aren't
	// filtered) but keeps the list tidy across repeat runs.
	if err := clearHiddenVmasForUID(targetUID); err != nil {
		logger.Debug("clear vma_hide", "uid", targetUID, "error", err)
	}

	const libAndroidPath = "/system/lib64/libandroid_runtime.so"
	const trapSymbol = "_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring"

	setArgV0Addr, err := FindSymbolAddress(zygotePid, libAndroidPath, "libandroid_runtime.so", trapSymbol)
	if err != nil {
		return 0, fmt.Errorf("resolve trap symbol: %w", err)
	}
	logger.Debug("resolved symbol", "symbol", "setArgV0", "addr", setArgV0Addr, "path", libAndroidPath)

	origBackup, err := ReadMem(zygotePid, setArgV0Addr, CUSTOM_TRAP_SIZE)
	if err != nil || len(origBackup) != CUSTOM_TRAP_SIZE {
		return 0, fmt.Errorf("read trap bytes: len=%d err=%w", len(origBackup), err)
	}

	linkerBase, err := GetModuleBase(zygotePid, "linker64")
	if err != nil {
		return 0, fmt.Errorf("linker64 base: %w", err)
	}
	const linkerPath = "/system/bin/linker64"
	dlopenOff, err := FindSymbolOffset(linkerPath, "__loader_dlopen")
	if err != nil {
		return 0, fmt.Errorf("resolve __loader_dlopen: %w", err)
	}
	dlopenAddr := linkerBase + dlopenOff
	logger.Debug("resolved symbol", "symbol", "__loader_dlopen", "addr", dlopenAddr, "path", linkerPath)

	stageImage, err := BuildDlopenStageImage(dlopenAddr, setArgV0Addr, libPath)
	if err != nil {
		return 0, err
	}
	stagePath := fmt.Sprintf("/data/local/tmp/.gzs.%d", time.Now().UnixNano())
	if err := os.WriteFile(stagePath, stageImage, 0755); err != nil {
		return 0, fmt.Errorf("write stage: %w", err)
	}
	_ = os.Chown(stagePath, targetUID, -1)
	defer os.Remove(stagePath)
	logger.Debug("stage written", "stage_path", stagePath, "size", len(stageImage))

	trap, err := BuildCustomLoaderShellcode(zygotePid, setArgV0Addr, stagePath, targetUID)
	if err != nil {
		return 0, err
	}

	prevChildren := ChildrenOf(zygotePid)
	logger.Debug("snapshot zygote children", "count", len(prevChildren))

	logger.Info("install trap", "addr", setArgV0Addr, "size", len(trap))
	if err := WriteMem(zygotePid, setArgV0Addr, trap); err != nil {
		return 0, fmt.Errorf("write trap: %w", err)
	}
	zygoteRestored := false
	restoreZygote := func() {
		if zygoteRestored {
			return
		}
		if err := WriteMem(zygotePid, setArgV0Addr, origBackup); err != nil {
			logger.Warn("restore zygote trap failed", "addr", setArgV0Addr, "error", err)
		} else {
			logger.Debug("zygote trap restored", "addr", setArgV0Addr)
		}
		zygoteRestored = true
	}
	defer restoreZygote()

	if err := exec.Command("am", "start", "-n", mainActivity).Run(); err != nil {
		return 0, fmt.Errorf("am start %s: %w", mainActivity, err)
	}

	logger.Info("waiting for child",
		"package", pkgName,
		"zygote_pid", zygotePid,
		"timeout_ms", childWaitTimeout.Milliseconds(),
	)
	childDeadline := time.Now().Add(childWaitTimeout)
	zygoteBase, err := GetModuleBase(zygotePid, "libandroid_runtime.so")
	if err != nil {
		return 0, fmt.Errorf("zygote libandroid_runtime base: %w", err)
	}

	var candidates []int
	seenCandidates := make(map[int]bool)
	for time.Now().Before(childDeadline) {
		for pid := range ChildrenOf(zygotePid) {
			if prevChildren[pid] || seenCandidates[pid] || !IsProcessAlive(pid) {
				continue
			}
			seenCandidates[pid] = true
			if processCmdlineContains(pid, pkgName) {
				candidates = append([]int{pid}, candidates...)
			} else {
				candidates = append(candidates, pid)
			}
		}
		if len(candidates) > 0 {
			break
		}
		time.Sleep(childPollInterval)
	}
	if len(candidates) == 0 {
		return 0, fmt.Errorf("timeout waiting for child process")
	}
	logger.Debug("child candidates", "count", len(candidates))

	// Restore zygote immediately so unrelated forks can't trigger the stub.
	restoreZygote()

	logger.Info("waiting for stage mailbox",
		"candidates", len(candidates),
		"mailbox_off", uint64(DLOPEN_STAGE_MAILBOX_OFF),
		"timeout_ms", stageWaitTimeout.Milliseconds(),
	)
	stageDeadline := time.Now().Add(stageWaitTimeout)
	var childPid int
	var childMailboxAddr uint64
	var childSetArgV0Addr uint64
	for time.Now().Before(stageDeadline) {
		for _, pid := range candidates {
			if !IsProcessAlive(pid) {
				continue
			}
			ranges, err := ParseMaps(pid)
			if err != nil {
				continue
			}
			// Single pass over the maps: locate the child's libandroid_runtime
			// base and any candidate stage RWX mappings simultaneously.
			var childBase uint64
			for _, r := range ranges {
				if childBase == 0 && r.Path != "" && strings.Contains(r.Path, "libandroid_runtime.so") {
					childBase = r.Start
				}
				if r.Perms != "rwxp" || r.Path != "" || r.End-r.Start < DLOPEN_STAGE_MAILBOX_OFF+32 {
					continue
				}
				mb := r.Start + DLOPEN_STAGE_MAILBOX_OFF
				val, err := ReadMem(pid, mb, 32)
				if err != nil || len(val) != 32 {
					continue
				}
				pidField := int(binary.LittleEndian.Uint64(val[8:16]))
				status := binary.LittleEndian.Uint64(val[16:24])
				if pidField == pid && status >= 1 && childBase != 0 {
					childPid = pid
					childMailboxAddr = mb
					childSetArgV0Addr = childBase + (setArgV0Addr - zygoteBase)
					break
				}
			}
			if childPid != 0 {
				break
			}
		}
		if childPid != 0 {
			break
		}
		time.Sleep(stagePollInterval)
	}
	if childPid == 0 {
		return 0, fmt.Errorf("stage mailbox timeout")
	}
	logger.Info("stage ready",
		"child_pid", childPid,
		"mailbox", childMailboxAddr,
		"value", uint64(1),
	)

	// Revert the trap in the child's setArgV0 page so the stage's BLR lands
	// on real code instead of looping back into our stub.
	if err := WriteMem(childPid, childSetArgV0Addr, origBackup); err != nil {
		return childPid, fmt.Errorf("restore child trap: %w", err)
	}
	logger.Debug("child trap restored",
		"addr", childSetArgV0Addr,
		"size", len(origBackup),
	)

	// Release the stage's spin: write 1 to the release slot at mailbox+24.
	const releaseSlot = 24
	if err := WriteMem(childPid, childMailboxAddr+releaseSlot, uint64Bytes(1)); err != nil {
		return childPid, fmt.Errorf("signal stage: %w", err)
	}
	logger.Debug("stage signaled",
		"mailbox", childMailboxAddr,
		"slot", uint64(releaseSlot),
		"value", uint64(1),
	)

	// Wait for setArgV0 + dlopen to complete (value >= 2 in the status slot).
	var handle uint64
	var observedValue uint64
	dlopenDeadline := time.Now().Add(dlopenWaitTimeout)
	for time.Now().Before(dlopenDeadline) {
		if !IsProcessAlive(childPid) {
			return childPid, fmt.Errorf("child exited before dlopen completion")
		}
		val, err := ReadMem(childPid, childMailboxAddr, 24)
		if err == nil && len(val) == 24 && binary.LittleEndian.Uint64(val[16:24]) >= 2 {
			handle = binary.LittleEndian.Uint64(val[0:8])
			observedValue = binary.LittleEndian.Uint64(val[16:24])
			break
		}
		time.Sleep(stagePollInterval)
	}
	if handle == 0 {
		logger.Warn("dlopen returned null or timed out — payload may not be loaded",
			"mailbox", childMailboxAddr,
		)
	} else {
		logger.Info("dlopen complete",
			"mailbox", childMailboxAddr,
			"value", observedValue,
			"handle", handle,
		)
	}

	// Wait for the stage to finish executing. The stage writes value=3 to
	// the status slot as its very last action before RET, so once we observe
	// it, the stage page is no longer running and we can safely tear down
	// the soinfo / hide the stage VMA. Bounded poll instead of a fixed sleep.
	var stageDoneValue uint64
	stageDoneDeadline := time.Now().Add(stageDoneTimeout)
	for time.Now().Before(stageDoneDeadline) {
		val, err := ReadMem(childPid, childMailboxAddr+16, 8)
		if err == nil && len(val) == 8 && binary.LittleEndian.Uint64(val) >= 3 {
			stageDoneValue = binary.LittleEndian.Uint64(val)
			break
		}
		time.Sleep(stagePollInterval)
	}
	if stageDoneValue >= 3 {
		logger.Debug("stage done",
			"mailbox", childMailboxAddr,
			"value", stageDoneValue,
		)
	} else {
		logger.Warn("stage done signal not observed",
			"mailbox", childMailboxAddr,
		)
	}
	if _, err := UnlinkSoinfo(childPid, targetUID, libPath, apiLevel); err != nil {
		logger.Warn("soinfo unlink failed (non-fatal)", "error", err)
	}

	// Hide the stage's 256 KB RWX anonymous region. The stage has already
	// returned by now; vma_hide only delists the VMA from /proc enumeration,
	// the pages stay mapped.
	stageBase := childMailboxAddr - DLOPEN_STAGE_MAILBOX_OFF
	stageEnd := stageBase + STAGE_REGION_SIZE
	if err := hideVma(targetUID, stageBase, stageEnd); err != nil {
		logger.Warn("stage vma_hide failed (non-fatal)", "error", err)
	} else {
		logger.Info("stage vma hidden", "stage_base", stageBase, "stage_end", stageEnd)
	}

	logger.Info("cloaked",
		"child_pid", childPid,
		"handle", handle,
		"uid", targetUID,
		"elapsed_ms", time.Since(startedAt).Milliseconds(),
	)
	return childPid, nil
}
