package main

import (
	"encoding/binary"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func RunInjector(pkgName string, libPath string, zygotePid int, mainActivity string) (int, error) {
	LogInfo("starting spawn injector", "package", pkgName, "mode", "in-place")

	libAndroidPath := "/system/lib64/libandroid_runtime.so"
	// _Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring
	setArgV0Addr, err := FindSymbolAddress(zygotePid, libAndroidPath, "libandroid_runtime.so", "_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring")
	if err != nil {
		return 0, err
	}
	LogDebug("resolved trap symbol", "symbol", "setArgV0", "addr", setArgV0Addr)

	// 1. Mailbox Setup (Agnostic Handshake)
	rwBase, err := GetModuleRWSegment(zygotePid, "libandroid_runtime.so")
	if err != nil {
		return 0, fmt.Errorf("failed to find RW segment: %v", err)
	}
	// Use a randomized offset within the RW segment to avoid signature-based detection
	mailboxAddr := rwBase + 0x1FF0
	WriteMem(zygotePid, mailboxAddr, make([]byte, 8))

	origBackup, _ := ReadMem(zygotePid, setArgV0Addr, 256) // Backup more for safety
	linkerBase, _ := GetModuleBase(zygotePid, "linker64")
	dlopenOffset, _ := FindSymbolOffset("/system/bin/linker64", "__loader_dlopen")
	dlopenAddr := linkerBase + dlopenOffset
	LogDebug("resolved loader symbol", "symbol", "dlopen", "addr", dlopenAddr)

	// 2. Build Shellcode Payload
	// The agnostic shellcode now includes open+unlink+dlopen for stealth:
	// - Opens the payload file
	// - Unlinks it from disk (file disappears immediately)
	// - Calls dlopen (kernel still serves from page cache)
	// - Closes the fd
	// This means the payload is gone from the filesystem before anti-tamper runs.
	trap := BuildAgnosticShellcode(zygotePid, setArgV0Addr, dlopenAddr, mailboxAddr, libPath, origBackup)

	LogInfo("recording zygote children")
	out, _ := exec.Command("pgrep", "-P", strconv.Itoa(zygotePid)).Output()
	prevChildren := make(map[int]bool)
	for _, f := range strings.Fields(string(out)) {
		pid, _ := strconv.Atoi(f)
		prevChildren[pid] = true
	}

	LogInfo("applying agnostic trap", "mailbox", mailboxAddr)
	WriteMem(zygotePid, setArgV0Addr, trap)
	defer func() {
		LogInfo("restoring zygote")
		WriteMem(zygotePid, setArgV0Addr, origBackup[:256])
	}()

	exec.Command("am", "start", "-n", mainActivity).Run()

	LogInfo("waiting for child process")
	var childPid int
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out, _ = exec.Command("pgrep", "-P", strconv.Itoa(zygotePid)).Output()
		for _, f := range strings.Fields(string(out)) {
			pid, _ := strconv.Atoi(f)
			if !prevChildren[pid] {
				childPid = pid
				break
			}
		}
		if childPid != 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if childPid == 0 {
		return 0, fmt.Errorf("timeout identifying child process")
	}
	LogInfo("identified child", "pid", childPid)

	// Resolve mailbox in child
	zygoteBase, _ := GetModuleBase(zygotePid, "libandroid_runtime.so")
	childBase, _ := GetModuleBase(childPid, "libandroid_runtime.so")
	childMailboxAddr := childBase + (mailboxAddr - zygoteBase)
	LogDebug("calculated child communication channel", "child_mailbox", childMailboxAddr)

	LogInfo("polling agnostic mailbox")
	for time.Now().Before(deadline) {
		val, err := ReadMem(childPid, childMailboxAddr, 8)
		if err == nil {
			handle := binary.LittleEndian.Uint64(val)
			if handle != 0 {
				LogInfo("handshake successful", "handle", handle, "type", "agnostic")
				return childPid, nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	return childPid, fmt.Errorf("agnostic handshake timeout")
}
