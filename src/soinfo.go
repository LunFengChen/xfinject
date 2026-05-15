package main

import (
	"fmt"
	"strings"
)

// soinfo unlinking — removes the injected library from the linker's internal
// linked list so that dl_iterate_phdr() no longer enumerates it.
//
// The linker maintains a singly-linked list of soinfo structs. Each node has:
//   - A "next" pointer (offset varies by Android version)
//   - A realpath/soname field for identification
//
// We walk the list via /proc/pid/mem, find the node matching our payload,
// and patch the previous node's "next" to skip it.

// SoinfoOffsets holds version-specific offsets into the soinfo struct.
// These are determined by the Android API level.
type SoinfoOffsets struct {
	// Offset of the "next" pointer within soinfo (soinfo* next)
	Next int
	// Offset of the realpath string (std::string or char[])
	// On Android 10+, this is a std::string (pointer to heap or SSO buffer)
	Realpath int
	// Size of std::string's inline buffer (SSO). If the path is short enough
	// it's stored inline; otherwise the first 8 bytes are a pointer to heap.
	StdStringInlineSize int
}

// GetSoinfoOffsets returns the soinfo struct offsets for common Android versions.
// These are based on AOSP bionic/linker/linker_soinfo.h
func GetSoinfoOffsets(apiLevel int) SoinfoOffsets {
	switch {
	case apiLevel >= 34: // Android 14+
		return SoinfoOffsets{Next: 0x28, Realpath: 0x1A8, StdStringInlineSize: 23}
	case apiLevel >= 33: // Android 13
		return SoinfoOffsets{Next: 0x28, Realpath: 0x1A0, StdStringInlineSize: 23}
	case apiLevel >= 31: // Android 12/12L
		return SoinfoOffsets{Next: 0x28, Realpath: 0x198, StdStringInlineSize: 23}
	case apiLevel >= 30: // Android 11
		return SoinfoOffsets{Next: 0x28, Realpath: 0x190, StdStringInlineSize: 23}
	case apiLevel >= 29: // Android 10
		return SoinfoOffsets{Next: 0x28, Realpath: 0x188, StdStringInlineSize: 23}
	default: // Android 9 and below (best effort)
		return SoinfoOffsets{Next: 0x28, Realpath: 0x180, StdStringInlineSize: 23}
	}
}

// readSoinfoRealpath reads the realpath from a soinfo node.
// Android's libc++ std::string uses SSO: if capacity <= 22 (on 64-bit),
// the string is stored inline. Otherwise, the first field is a pointer to heap data.
func readSoinfoRealpath(pid int, soinfoAddr uint64, offsets SoinfoOffsets) (string, error) {
	// Read the std::string structure (24 bytes for SSO on arm64)
	strAddr := soinfoAddr + uint64(offsets.Realpath)
	strData, err := ReadMem(pid, strAddr, 32)
	if err != nil {
		return "", err
	}

	// libc++ std::string layout (little-endian, 64-bit):
	// Short string (SSO): byte[0] bit 0 = 0, length in byte[1], data at byte[1..22]
	// Long string: byte[0] bit 0 = 1, capacity in bytes[0..7], size in [8..15], pointer in [16..23]
	//
	// Actually on Android's libc++ (arm64):
	// __short: { __size_ (1 byte, value = len << 1, bit0=0 for short), __data_[23] }
	// __long:  { __cap_ (8 bytes, bit0=1 for long), __size_ (8 bytes), __data_ (8 bytes = pointer) }

	isLong := (strData[0] & 1) != 0

	if isLong {
		// Long string: pointer is at offset 16 within the std::string
		ptr := uint64(strData[16]) | uint64(strData[17])<<8 | uint64(strData[18])<<16 |
			uint64(strData[19])<<24 | uint64(strData[20])<<32 | uint64(strData[21])<<40 |
			uint64(strData[22])<<48 | uint64(strData[23])<<56
		if ptr == 0 {
			return "", nil
		}
		return ReadString(pid, ptr, 256)
	}

	// Short string: length is strData[0] >> 1, data starts at strData[1]
	length := int(strData[0] >> 1)
	if length > 22 {
		length = 22
	}
	if length == 0 {
		return "", nil
	}
	return string(strData[1 : 1+length]), nil
}

// UnlinkSoinfo removes the specified library from the linker's soinfo linked list
// in the target process. After this call, dl_iterate_phdr() will not enumerate it.
//
// Parameters:
//   - pid: target process ID
//   - payloadPath: the path (or substring) of the library to hide
//   - apiLevel: Android API level (29=Android10, 30=11, 31=12, 33=13, 34=14)
func UnlinkSoinfo(pid int, payloadPath string, apiLevel int) error {
	offsets := GetSoinfoOffsets(apiLevel)

	// Find the solist head. It's stored in a global variable in linker64.
	// Symbol: __dl__ZL6solist (static local in linker)
	// We try to resolve it; if that fails, we scan for it.
	linkerBase, err := GetModuleBase(pid, "linker64")
	if err != nil {
		return fmt.Errorf("cannot find linker64: %w", err)
	}

	// Try multiple known symbol names for the soinfo list head
	solistSymbols := []string{
		"__dl__ZL6solist",
		"__dl_solist",
	}

	var solistAddr uint64
	for _, sym := range solistSymbols {
		offset, err := FindSymbolOffset("/system/bin/linker64", sym)
		if err == nil {
			solistAddr = linkerBase + offset
			LogDebug("found solist symbol", "symbol", sym, "addr", solistAddr)
			break
		}
		// Try apex path
		offset, err = FindSymbolOffset("/apex/com.android.runtime/bin/linker64", sym)
		if err == nil {
			solistAddr = linkerBase + offset
			LogDebug("found solist symbol (apex)", "symbol", sym, "addr", solistAddr)
			break
		}
	}

	if solistAddr == 0 {
		// Fallback: scan for solist by heuristic
		solistAddr, err = findSolistByHeuristic(pid, linkerBase)
		if err != nil {
			return fmt.Errorf("cannot locate solist: %w", err)
		}
	}

	// Read the head of the soinfo list
	headPtr, err := ReadPointer(pid, solistAddr)
	if err != nil {
		return fmt.Errorf("cannot read solist head: %w", err)
	}
	if headPtr == 0 {
		return fmt.Errorf("solist head is null")
	}

	LogDebug("walking soinfo list", "head", headPtr)

	// Walk the linked list
	var prevAddr uint64 // address of the previous node's "next" field
	current := headPtr
	iterations := 0
	maxIterations := 512 // safety limit

	for current != 0 && iterations < maxIterations {
		iterations++

		// Read realpath from this node
		path, err := readSoinfoRealpath(pid, current, offsets)
		if err != nil {
			LogDebug("failed to read soinfo realpath", "addr", current, "error", err)
			// Continue walking even if one node fails
		} else if path != "" && strings.Contains(path, payloadPath) {
			LogInfo("found payload soinfo node", "addr", current, "path", path)

			// Read the target's "next" pointer
			targetNext, err := ReadPointer(pid, current+uint64(offsets.Next))
			if err != nil {
				return fmt.Errorf("cannot read target next pointer: %w", err)
			}

			if prevAddr == 0 {
				// Target is the head — update the solist global
				LogDebug("unlinking soinfo head node")
				if err := WritePointer(pid, solistAddr, targetNext); err != nil {
					return fmt.Errorf("failed to update solist head: %w", err)
				}
			} else {
				// Patch previous node's next to skip target
				LogDebug("unlinking soinfo node", "prev_next_addr", prevAddr)
				if err := WritePointer(pid, prevAddr, targetNext); err != nil {
					return fmt.Errorf("failed to patch prev->next: %w", err)
				}
			}

			LogInfo("soinfo unlinked successfully", "path", path)
			return nil
		}

		// Advance: prevAddr = &current->next, current = current->next
		prevAddr = current + uint64(offsets.Next)
		current, err = ReadPointer(pid, prevAddr)
		if err != nil {
			return fmt.Errorf("cannot read next pointer at %#x: %w", prevAddr, err)
		}
	}

	if iterations >= maxIterations {
		return fmt.Errorf("soinfo walk exceeded %d iterations (possible corruption)", maxIterations)
	}

	return fmt.Errorf("payload %q not found in soinfo list", payloadPath)
}

// findSolistByHeuristic attempts to locate the solist global by scanning
// linker64's .bss/.data sections for a pointer that looks like a valid soinfo head.
func findSolistByHeuristic(pid int, linkerBase uint64) (uint64, error) {
	// Get the RW segment of linker64 (contains .data and .bss)
	ranges, err := ParseMaps(pid)
	if err != nil {
		return 0, err
	}

	for _, r := range ranges {
		if !strings.Contains(r.Path, "linker64") {
			continue
		}
		if !strings.Contains(r.Perms, "rw") {
			continue
		}

		// Scan this region for pointers that could be soinfo heads
		// A valid soinfo pointer should point into a mapped region
		regionSize := int(r.End - r.Start)
		if regionSize > 0x10000 {
			regionSize = 0x10000 // cap scan size
		}

		data, err := ReadMem(pid, r.Start, regionSize)
		if err != nil {
			continue
		}

		for off := 0; off+8 <= len(data); off += 8 {
			ptr := uint64(data[off]) | uint64(data[off+1])<<8 | uint64(data[off+2])<<16 |
				uint64(data[off+3])<<24 | uint64(data[off+4])<<32 | uint64(data[off+5])<<40 |
				uint64(data[off+6])<<48 | uint64(data[off+7])<<56

			if ptr == 0 || ptr < 0x7000000000 {
				continue
			}

			// Try to read a realpath from this candidate
			offsets := GetSoinfoOffsets(33) // default to Android 13
			path, err := readSoinfoRealpath(pid, ptr, offsets)
			if err != nil || path == "" {
				continue
			}

			// If the path looks like a real library, this might be solist
			if strings.HasPrefix(path, "/") && strings.Contains(path, ".so") {
				LogDebug("heuristic solist candidate", "addr", r.Start+uint64(off), "first_path", path)
				return r.Start + uint64(off), nil
			}
		}
	}

	return 0, fmt.Errorf("heuristic scan failed to find solist")
}
