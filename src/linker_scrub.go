package main

import (
	"fmt"
	"strings"
)

// ScrubLinkerArtifacts removes traces of the loaded payload from the linker's
// internal data structures that aren't covered by soinfo unlinking.
//
// This includes:
//   - The dlerror buffer (may contain the payload path from the last dlopen)
//   - Debug verbosity strings
//   - The linker's internal path cache
//
// All operations are performed via /proc/pid/mem from the injector side.
func ScrubLinkerArtifacts(pid int, payloadPath string) error {
	linkerBase, err := GetModuleBase(pid, "linker64")
	if err != nil {
		return fmt.Errorf("cannot find linker64: %w", err)
	}

	// Scrub any occurrence of the payload path in linker's RW segments
	ranges, err := ParseMaps(pid)
	if err != nil {
		return fmt.Errorf("cannot read maps: %w", err)
	}

	scrubbed := 0
	for _, r := range ranges {
		if !strings.Contains(r.Path, "linker64") {
			continue
		}
		if !strings.Contains(r.Perms, "rw") {
			continue
		}

		regionSize := int(r.End - r.Start)
		if regionSize > 0x100000 { // cap at 1MB
			regionSize = 0x100000
		}

		data, err := ReadMem(pid, r.Start, regionSize)
		if err != nil {
			continue
		}

		// Search for the payload path string in this region
		pathBytes := []byte(payloadPath)
		offset := 0
		for {
			idx := findBytes(data[offset:], pathBytes)
			if idx < 0 {
				break
			}
			absOffset := offset + idx
			addr := r.Start + uint64(absOffset)

			// Zero out the string
			zeros := make([]byte, len(pathBytes))
			if err := WriteMem(pid, addr, zeros); err != nil {
				LogWarn("failed to scrub linker string", "addr", addr, "error", err)
			} else {
				scrubbed++
			}
			offset = absOffset + len(pathBytes)
		}
	}

	// Also scrub the payload path from libandroid_runtime.so RW segments
	// (the dlopen path may be cached there too)
	for _, r := range ranges {
		if !strings.Contains(r.Path, "libandroid_runtime.so") {
			continue
		}
		if !strings.Contains(r.Perms, "rw") {
			continue
		}

		regionSize := int(r.End - r.Start)
		if regionSize > 0x100000 {
			regionSize = 0x100000
		}

		data, err := ReadMem(pid, r.Start, regionSize)
		if err != nil {
			continue
		}

		pathBytes := []byte(payloadPath)
		offset := 0
		for {
			idx := findBytes(data[offset:], pathBytes)
			if idx < 0 {
				break
			}
			absOffset := offset + idx
			addr := r.Start + uint64(absOffset)
			zeros := make([]byte, len(pathBytes))
			if err := WriteMem(pid, addr, zeros); err != nil {
				LogWarn("failed to scrub runtime string", "addr", addr, "error", err)
			} else {
				scrubbed++
			}
			offset = absOffset + len(pathBytes)
		}
	}

	if scrubbed > 0 {
		LogInfo("scrubbed linker artifacts", "count", scrubbed)
	} else {
		LogDebug("no linker artifacts found to scrub")
	}

	_ = linkerBase // used for potential future symbol-based scrubbing
	return nil
}

// ScrubPayloadPathEverywhere does a comprehensive scan of all writable memory
// in the target process and zeros out any occurrence of the payload path.
// This is the nuclear option — use after soinfo unlinking and remap.
func ScrubPayloadPathEverywhere(pid int, payloadPath string) error {
	ranges, err := ParseMaps(pid)
	if err != nil {
		return fmt.Errorf("cannot read maps: %w", err)
	}

	scrubbed := 0
	pathBytes := []byte(payloadPath)

	for _, r := range ranges {
		// Only scan writable regions
		if !strings.Contains(r.Perms, "w") {
			continue
		}
		// Skip very large regions (stack, heap) to avoid performance issues
		regionSize := int(r.End - r.Start)
		if regionSize > 4*1024*1024 { // 4MB cap per region
			continue
		}

		data, err := ReadMem(pid, r.Start, regionSize)
		if err != nil {
			continue
		}

		offset := 0
		for {
			idx := findBytes(data[offset:], pathBytes)
			if idx < 0 {
				break
			}
			absOffset := offset + idx
			addr := r.Start + uint64(absOffset)
			zeros := make([]byte, len(pathBytes))
			if err := WriteMem(pid, addr, zeros); err == nil {
				scrubbed++
			}
			offset = absOffset + len(pathBytes)
		}
	}

	if scrubbed > 0 {
		LogInfo("scrubbed payload path from memory", "count", scrubbed)
	}
	return nil
}

// findBytes returns the index of needle in haystack, or -1 if not found.
func findBytes(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
