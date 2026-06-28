package xfinject

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
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
	detectTimeout = 20 * time.Second
	// dlopenTimeout: per-payload cap on how long we wait for the stage's
	// __loader_dlopen of one payload to complete after we open its gate.
	dlopenTimeout = 10 * time.Second
	// stageDoneTimeout: time we'll wait for the stage to write its final
	// status=3 (about-to-RET) marker so we know the RWX page is no longer
	// executing before we tear down the soinfo / hide the VMA.
	stageDoneTimeout = 1 * time.Second
	// pollInterval: cadence of the deadline-bounded polling loops.  2 ms is
	// short enough to barely add latency to a 200 ms total, cheap enough that
	// 500 polls/sec of single-pid /proc/mem reads is invisible CPU.
	pollInterval = 2 * time.Millisecond
)

func uint64Bytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func discardTrapPageBestEffort(pid int, addr uint64, size int, reason string, attrs ...any) {
	err := DiscardRemotePrivatePages(pid, addr, size)
	logAttrs := append([]any{"pid", pid, "addr", addr}, attrs...)
	if err == nil {
		logger.Debug("trap page private copy discarded", append(logAttrs, "reason", reason)...)
		return
	}
	if errors.Is(err, ErrRemoteDiscardUnsupported) {
		logger.Debug("trap page private-copy discard unavailable; continuing with byte-level restore",
			append(logAttrs, "reason", reason, "error", err)...)
		return
	}
	logger.Debug("trap page private-copy discard failed; continuing with byte-level restore",
		append(logAttrs, "reason", reason, "error", err)...)
}

// RunInjector orchestrates the stub-and-stage injection:
//   - patches a 428-byte stub at zygote's setArgV0;
//   - on the first matching fork, the stub mmaps the stage from a file and
//     branches to it;
//   - the stage announces itself via a mailbox at a fixed offset inside its
//     own anonymous RWX mapping, then spins;
//   - the injector restores the child's setArgV0 page, releases the spin, then
//     gates each payload in libPaths (in order): it waits for that payload's
//     dlopen to complete and acks so the stage advances to the next. Once every
//     payload is loaded it unlinks each one's soinfo + hides its VMA ranges,
//     then hides the stage region.
//
// libPaths are loaded in the given order into the single trapped child.
// apiLevel selects the right soinfo struct offsets for the running Android
// version (resolved at startup via getprop ro.build.version.sdk).
func RunInjector(pkgName string, libPaths []string, zygotePid int, mainActivity string, apiLevel int, launchActivity bool, waitTimeout time.Duration, autostartSymbol, autostartArg string) (int, error) {
	startedAt := time.Now()
	logger.Info("stage injector start", "package", pkgName, "api", apiLevel)

	targetUID := GetAppUID(pkgName)
	if targetUID <= 0 {
		return 0, fmt.Errorf("resolve uid for %s", pkgName)
	}
	logger.Debug("resolved app uid", "package", pkgName, "uid", targetUID)

	// Clear any stale per-UID entries from a previous injection into this app.
	// This is intentionally forced even when the current run has --vma-hide=never:
	// KPM state is kernel-global and may outlive the previous xfinject process,
	// so an old xfvmahide entry can hide the newly-created stage mapping from
	// /proc/<pid>/maps before this run has opted into hiding anything.
	if err := clearHiddenVmasForUID(targetUID, true); err != nil {
		logger.Debug("clear stale vma_hide", "uid", targetUID, "error", err)
	} else {
		logger.Debug("cleared stale vma_hide", "uid", targetUID)
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
	discardTrapPageBestEffort(zygotePid, setArgV0Addr, CUSTOM_TRAP_SIZE, "pre-injection self-heal")

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

	var dlsymAddr uint64
	if autostartSymbol != "" {
		dlsymName := "dlsym"
		dlsymOff, err := FindSymbolOffset(linkerPath, dlsymName)
		if err != nil {
			dlsymName = "__loader_dlsym"
			dlsymOff, err = FindSymbolOffset(linkerPath, dlsymName)
			if err != nil {
				return 0, fmt.Errorf("resolve dlsym for autostart: %w", err)
			}
		}
		dlsymAddr = linkerBase + dlsymOff
		logger.Debug("resolved symbol", "symbol", dlsymName, "addr", dlsymAddr, "path", linkerPath)
	}

	stageImage, err := BuildDlopenStageImage(dlopenAddr, dlsymAddr, setArgV0Addr, libPaths, autostartSymbol, autostartArg)
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

	trap, err := BuildStubShellcode(zygotePid, setArgV0Addr, stagePath, targetUID)
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
		discardTrapPageBestEffort(zygotePid, setArgV0Addr, CUSTOM_TRAP_SIZE, "restore zygote trap")
		logger.Debug("zygote trap restored", "addr", setArgV0Addr)
		zygoteRestored = true
	}
	defer restoreZygote()

	if launchActivity {
		// --activity-clear-task forces a cold respawn even if a stale task record
		// exists (e.g. from a prior force-stop or failed injection), so zygote
		// always forks a fresh child for our trap to catch.
		if err := LaunchPackage(pkgName, mainActivity); err != nil {
			return 0, fmt.Errorf("launch %s: %w", pkgName, err)
		}
	} else {
		logger.Info("waiting for natural app launch", "package", pkgName)
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
	if waitTimeout <= 0 {
		waitTimeout = detectTimeout
	}
	detectDeadline := time.Now().Add(waitTimeout)
	logger.Info("waiting for stage",
		"package", pkgName,
		"zygote_pid", zygotePid,
		"mailbox_off", uint64(DLOPEN_STAGE_MAILBOX_OFF),
		"timeout_ms", waitTimeout.Milliseconds(),
	)
	var childPid int
	var childMailboxAddr uint64
	var childSetArgV0Addr uint64
	loggedCandidates := make(map[int]bool)
	for time.Now().Before(detectDeadline) {
		for pid := range ChildrenOf(zygotePid) {
			if prevChildren[pid] || !IsProcessAlive(pid) {
				continue
			}
			ranges, err := ParseMaps(pid)
			if err != nil {
				if !loggedCandidates[pid] {
					logger.Debug("stage candidate maps unavailable", "pid", pid, "error", err)
					loggedCandidates[pid] = true
				}
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
			if !loggedCandidates[pid] {
				rwxAnon := 0
				for _, r := range ranges {
					if r.Perms == "rwxp" && r.Path == "" {
						rwxAnon++
					}
				}
				trapState := "unknown"
				trapHead := ""
				if childBase != 0 {
					childTrapAddr := childBase + (setArgV0Addr - zygoteBase)
					if b, err := ReadMem(pid, childTrapAddr, min(16, len(trap))); err == nil {
						trapHead = fmt.Sprintf("%x", b)
						switch {
						case len(b) <= len(trap) && bytes.Equal(b, trap[:len(b)]):
							trapState = "installed"
						case len(b) <= len(origBackup) && bytes.Equal(b, origBackup[:len(b)]):
							trapState = "original"
						default:
							trapState = "other"
						}
					}
				}
				cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
				cmdlineText := strings.ReplaceAll(string(cmdline), "\x00", " ")
				statusUID := ""
				if status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
					for _, line := range strings.Split(string(status), "\n") {
						if strings.HasPrefix(line, "Uid:") {
							statusUID = strings.TrimSpace(line)
							break
						}
					}
				}
				logger.Debug("stage candidate observed",
					"pid", pid,
					"cmdline", strings.TrimSpace(cmdlineText),
					"status_uid", statusUID,
					"maps", len(ranges),
					"child_base", childBase,
					"rwx_anon", rwxAnon,
					"trap_state", trapState,
					"trap_head", trapHead,
				)
				loggedCandidates[pid] = true
			}
			if childBase == 0 {
				continue
			}
			// Second pass: find the stage's RWX anonymous region and match the
			// pid + status it wrote into its mailbox.
			for _, r := range ranges {
				if r.Perms != "rwxp" || r.Path != "" || r.End-r.Start < DLOPEN_STAGE_MAILBOX_OFF+DLOPEN_STAGE_MAILBOX_SIZE {
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
	discardTrapPageBestEffort(childPid, childSetArgV0Addr, CUSTOM_TRAP_SIZE, "restore child trap")
	logger.Debug("child trap restored",
		"addr", childSetArgV0Addr,
		"size", len(origBackup),
	)

	// Mailbox slot layout (see stage_dlopen.s): [0]=handle [8]=pid [16]=status
	// [24]=gate (injector->stage counter) [32]=loaded (stage->injector counter).
	const (
		gateSlot   = 24
		loadedSlot = 32
	)

	// Release the stage's single setArgV0 call: gate=1. The child's trap page is
	// restored, so the stage's BLR now lands on real code.
	if err := WriteMem(childPid, childMailboxAddr+gateSlot, uint64Bytes(1)); err != nil {
		return childPid, fmt.Errorf("signal stage: %w", err)
	}
	logger.Debug("stage signaled", "mailbox", childMailboxAddr, "slot", uint64(gateSlot), "value", uint64(1))

	// Gated load loop. The stage loads libPaths in order; for each payload i it
	// publishes loaded>=i+1 once its dlopen returns (handle in the handle slot,
	// held stable until we ack), then spins for gate>=i+2. We confirm the handle
	// and ack so the stage advances to payload i+1.
	//
	// The soinfo-unlink + VMA-hide teardown is DEFERRED to after every payload is
	// loaded (below). Unlinking a soinfo that happens to be the linker's solist
	// tail leaves the linker's internal tail pointer dangling at the orphaned
	// node, so the NEXT dlopen chains its soinfo onto that node and becomes
	// unreachable from the list head — which silently dropped payload i+1 from
	// the walk. Tearing everything down only once loading is finished keeps the
	// chain intact for every payload and matches the original post-stage timing.
	for i, libPath := range libPaths {
		var handle uint64
		gotLoaded := false
		dlopenDeadline := time.Now().Add(dlopenTimeout)
		for time.Now().Before(dlopenDeadline) {
			if !IsProcessAlive(childPid) {
				return childPid, fmt.Errorf("child exited before dlopen of payload %d (%s)", i, libPath)
			}
			val, err := ReadMem(childPid, childMailboxAddr, loadedSlot+8)
			if err == nil && len(val) == loadedSlot+8 &&
				binary.LittleEndian.Uint64(val[loadedSlot:loadedSlot+8]) >= uint64(i+1) {
				handle = binary.LittleEndian.Uint64(val[0:8])
				gotLoaded = true
				break
			}
			time.Sleep(pollInterval)
		}
		if !gotLoaded {
			logger.Warn("dlopen wait timed out — payload may not be loaded",
				"index", i, "payload", libPath, "mailbox", childMailboxAddr)
		} else if handle == 0 {
			logger.Warn("dlopen returned null — payload not loaded", "index", i, "payload", libPath)
		} else {
			logger.Info("dlopen complete", "index", i, "payload", libPath, "handle", handle)
		}

		// Ack payload i: gate=i+2 releases the stage to the next payload (or, for
		// the last one, to its final madvise + status=3 + RET).
		if err := WriteMem(childPid, childMailboxAddr+gateSlot, uint64Bytes(uint64(i+2))); err != nil {
			return childPid, fmt.Errorf("ack payload %d: %w", i, err)
		}
		logger.Debug("payload acked", "index", i, "slot", uint64(gateSlot), "value", uint64(i+2))
	}

	// Wait for the stage to finish executing. The stage writes status=3 as its
	// very last action before RET, so once we observe it the stage page is no
	// longer running. Bounded poll instead of a fixed sleep.
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
		logger.Debug("stage done", "mailbox", childMailboxAddr, "value", stageDoneValue)
	} else {
		logger.Warn("stage done signal not observed", "mailbox", childMailboxAddr)
	}

	// Per-payload teardown, now that every payload is loaded: unlink each soinfo
	// from the solist and hide its VMA ranges. UnlinkSoinfo walks from the list
	// head and re-links prev->next each time, so the remaining payloads stay
	// reachable regardless of unlink order. Matches by the staged path, unique
	// per payload.
	soinfoUnlinked := 0
	vmaRangesTotal, vmaHiddenTotal := 0, 0
	for i, libPath := range libPaths {
		hr, err := UnlinkSoinfo(childPid, targetUID, libPath, apiLevel)
		if err != nil {
			logger.Warn("soinfo unlink failed (non-fatal)", "index", i, "payload", libPath, "error", err)
		}
		if hr.Unlinked {
			soinfoUnlinked++
		}
		vmaRangesTotal += hr.VmaRanges
		vmaHiddenTotal += hr.VmaHidden
	}

	// Hide the stage's 256 KB RWX anonymous region (when vma_hide is active). The
	// stage has already returned by now; vma_hide only delists the VMA from /proc
	// enumeration, the pages stay mapped.
	stageHidden := false
	if VmaHideUsable() {
		stageBase := childMailboxAddr - DLOPEN_STAGE_MAILBOX_OFF
		stageEnd := stageBase + STAGE_REGION_SIZE
		if err := hideVma(targetUID, stageBase, stageEnd); err != nil {
			logger.Warn("stage vma_hide failed (non-fatal)", "error", err)
		} else {
			stageHidden = true
			logger.Info("stage vma hidden", "stage_base", stageBase, "stage_end", stageEnd)
		}
	}

	// Every payload is dlopen'd by now (the mapping persists independently of the
	// file), so the on-disk sandbox copies are pure forensic residue — remove them.
	// A crash before this point is covered by the failure-path cleanup in main.go.
	for _, p := range libPaths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			logger.Debug("staged payload remove failed", "path", p, "error", err)
		}
	}

	// Honest terminal status. "cloaked" is reserved for a run where every required
	// hide step actually succeeded; otherwise we report "loaded" and spell out what
	// is still visible, so a degraded run is never mistaken for full stealth — and
	// --vma-hide=never (which hides nothing by design) is never labelled cloaked.
	allUnlinked := soinfoUnlinked == len(libPaths)
	payloadsHidden := vmaRangesTotal > 0 && vmaHiddenTotal == vmaRangesTotal
	fullyHidden := VmaHideUsable() && allUnlinked && payloadsHidden && stageHidden
	status := []any{
		"child_pid", childPid,
		"payloads", len(libPaths),
		"uid", targetUID,
		"soinfo_unlinked", fmt.Sprintf("%d/%d", soinfoUnlinked, len(libPaths)),
		"vma_hide", VmaHideUsable(),
		"payload_vmas", fmt.Sprintf("%d/%d", vmaHiddenTotal, vmaRangesTotal),
		"stage_hidden", stageHidden,
		"elapsed_ms", time.Since(startedAt).Milliseconds(),
	}
	switch {
	case fullyHidden:
		logger.Info("cloaked", status...)
	case !VmaHideUsable():
		logger.Info("loaded — vma_hide inactive, payload visible in /proc/maps", status...)
	case VmaHideStrict():
		// Operator demanded hiding (--vma-hide=always) but it did not fully take.
		logger.Error("loaded but NOT fully hidden despite --vma-hide=always", status...)
	default:
		logger.Warn("loaded — degraded hiding (partially visible)", status...)
	}
	return childPid, nil
}
