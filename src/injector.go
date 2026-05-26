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

// Bounded waits for the cross-process handshake.  Every loop in RunInjector
// uses a deadline + short-poll pattern (never a blanket time.Sleep), so these
// values are upper bounds on legit waiting time — the typical successful
// injection completes the whole chain in 200–400 ms.
const (
	// detectTimeout caps how long we wait for our trap to fire in the target
	// child AND for the stage to announce itself via the mailbox.  These were
	// previously two separate timeouts (child-fork wait + stage-mailbox wait),
	// but the loops were merged into one self-identifying scan (matching by the
	// stage's own getpid() in the mailbox), so a single deadline is honest.
	detectTimeout     = 20 * time.Second
	// dlopenTimeout: time we'll wait for the stage to finish its inline
	// __loader_dlopen of the payload after we release the spin lock.
	dlopenTimeout     = 10 * time.Second
	// stageDoneTimeout: time we'll wait for the stage to write its final
	// status=3 (about-to-RET) marker so we know the RWX page is no longer
	// executing before we tear down the soinfo / hide the VMA.
	stageDoneTimeout  = 1 * time.Second
	// pollInterval: cadence of the deadline-bounded polling loops.  2 ms is
	// short enough to barely add latency to a 200 ms total, cheap enough that
	// 500 polls/sec of single-pid /proc/mem reads is invisible CPU.
	pollInterval      = 2 * time.Millisecond
)

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

	// Read the pristine bytes from disk and compare against zygote's in-mem
	// copy.  If they differ, a prior failed run left our stub in place —
	// restore from disk before doing anything else, otherwise every fork
	// will hit the stale trap and loop in _orig.
	setArgV0Off, err := FindSymbolOffset(libAndroidPath, trapSymbol)
	if err != nil {
		return 0, fmt.Errorf("resolve trap symbol offset: %w", err)
	}
	libAndroidBytes, err := os.ReadFile(libAndroidPath)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", libAndroidPath, err)
	}
	if int(setArgV0Off)+CUSTOM_TRAP_SIZE > len(libAndroidBytes) {
		return 0, fmt.Errorf("trap offset %d+%d exceeds %s size %d",
			setArgV0Off, CUSTOM_TRAP_SIZE, libAndroidPath, len(libAndroidBytes))
	}
	diskBytes := libAndroidBytes[setArgV0Off : int(setArgV0Off)+CUSTOM_TRAP_SIZE]

	origBackup, err := ReadMem(zygotePid, setArgV0Addr, CUSTOM_TRAP_SIZE)
	if err != nil || len(origBackup) != CUSTOM_TRAP_SIZE {
		return 0, fmt.Errorf("read trap bytes: len=%d err=%w", len(origBackup), err)
	}
	if !bytes.Equal(origBackup, diskBytes) {
		logger.Warn("zygote setArgV0 differs from on-disk; self-healing before injection",
			"addr", setArgV0Addr, "size", CUSTOM_TRAP_SIZE)
		if err := WriteMem(zygotePid, setArgV0Addr, diskBytes); err != nil {
			return 0, fmt.Errorf("self-heal write: %w", err)
		}
		verify, err := ReadMem(zygotePid, setArgV0Addr, CUSTOM_TRAP_SIZE)
		if err != nil || !bytes.Equal(verify, diskBytes) {
			return 0, fmt.Errorf("self-heal verify failed: zygote bytes still differ from disk")
		}
		logger.Info("zygote self-healed from disk", "addr", setArgV0Addr)
		origBackup = diskBytes
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
	stageName, err := randomChromiumName()
	if err != nil {
		return 0, err
	}
	stagePath, err := writeIntoAppSandbox(pkgName, stageName, stageImage, 0755, targetUID)
	if err != nil {
		return 0, fmt.Errorf("write stage: %w", err)
	}
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
			logger.Error("restore zygote trap WRITE failed — stub still installed; next run will self-heal",
				"addr", setArgV0Addr, "error", err)
			return
		}
		// Verify the write landed.  /proc/<pid>/mem can silently no-op on some
		// kernels (e.g. when the page is marked unwritable mid-flight), and
		// leaving the stub in zygote bricks every subsequent fork until reboot.
		after, err := ReadMem(zygotePid, setArgV0Addr, CUSTOM_TRAP_SIZE)
		if err != nil {
			logger.Error("restore zygote trap VERIFY-READ failed",
				"addr", setArgV0Addr, "error", err)
			return
		}
		if !bytes.Equal(after, origBackup) {
			logger.Error("restore zygote trap VERIFY MISMATCH — stub still installed; next run will self-heal",
				"addr", setArgV0Addr)
			return
		}
		logger.Debug("zygote trap restored", "addr", setArgV0Addr)
		zygoteRestored = true
	}
	defer restoreZygote()

	// --activity-clear-task forces a cold respawn even if a stale task record
	// exists (e.g. from a prior force-stop or failed injection), so zygote
	// always forks a fresh child for our trap to catch.
	if err := exec.Command("am", "start", "--activity-clear-task", "-n", mainActivity).Run(); err != nil {
		return 0, fmt.Errorf("am start %s: %w", mainActivity, err)
	}

	zygoteBase, err := GetModuleBase(zygotePid, "libandroid_runtime.so")
	if err != nil {
		return 0, fmt.Errorf("zygote libandroid_runtime base: %w", err)
	}

	// Self-identifying scan: poll all new zygote children, look in each for an
	// RWX anon region whose mailbox's pid slot matches the candidate's pid and
	// status >= 1. The stage writes getpid() into the mailbox itself, so the
	// match is unambiguous — no cmdline guessing, no racy ordering with unrelated
	// background services that fork from zygote concurrently.
	detectDeadline := time.Now().Add(detectTimeout)
	logger.Info("waiting for stage",
		"package", pkgName,
		"zygote_pid", zygotePid,
		"mailbox_off", uint64(DLOPEN_STAGE_MAILBOX_OFF),
		"timeout_ms", detectTimeout.Milliseconds(),
	)
	var childPid int
	var childMailboxAddr uint64
	var childSetArgV0Addr uint64
	for time.Now().Before(detectDeadline) {
		for pid := range ChildrenOf(zygotePid) {
			if prevChildren[pid] || !IsProcessAlive(pid) {
				continue
			}
			ranges, err := ParseMaps(pid)
			if err != nil {
				continue
			}
			// First pass: locate libandroid_runtime.so base. This MUST be a
			// separate pass from the rwxp scan below: ASLR places the stage's
			// anonymous region either below or above libandroid_runtime.so, and
			// the maps are address-sorted. Discovering childBase inline meant
			// that whenever the stage region sorted first (lower address), the
			// match was gated on a childBase that was still 0, so the spinning
			// child was skipped — detection then succeeded or timed out at
			// random depending on the per-boot ASLR layout.
			var childBase uint64
			for _, r := range ranges {
				if r.Path != "" && strings.Contains(r.Path, "libandroid_runtime.so") {
					childBase = r.Start
					break
				}
			}
			if childBase == 0 {
				continue
			}
			// Second pass: find the stage's RWX anonymous region and match the
			// pid + status it wrote into its mailbox.
			for _, r := range ranges {
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
				if pidField == pid && status >= 1 {
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
		time.Sleep(pollInterval)
	}
	if childPid == 0 {
		return 0, fmt.Errorf("stage mailbox timeout (no matching child appeared)")
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
	dlopenDeadline := time.Now().Add(dlopenTimeout)
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
		time.Sleep(pollInterval)
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
		time.Sleep(pollInterval)
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
