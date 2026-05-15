package main

import (
	"fmt"
	"strings"
)

// SoinfoOffsets holds version-specific offsets into the soinfo struct.
type SoinfoOffsets struct {
	Next                int
	Realpath            int
	StdStringInlineSize int
}

func GetSoinfoOffsets(apiLevel int) SoinfoOffsets {
	switch {
	case apiLevel >= 34:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x1A8, StdStringInlineSize: 23}
	case apiLevel >= 33:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x1A0, StdStringInlineSize: 23}
	case apiLevel >= 31:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x198, StdStringInlineSize: 23}
	case apiLevel >= 30:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x190, StdStringInlineSize: 23}
	case apiLevel >= 29:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x188, StdStringInlineSize: 23}
	default:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x180, StdStringInlineSize: 23}
	}
}

func readSoinfoRealpath(pid int, soinfoAddr uint64, offsets SoinfoOffsets) (string, error) {
	strAddr := soinfoAddr + uint64(offsets.Realpath)
	strData, err := ReadMem(pid, strAddr, 32)
	if err != nil {
		return "", err
	}

	isLong := (strData[0] & 1) != 0
	if isLong {
		ptr := uint64(strData[16]) | uint64(strData[17])<<8 | uint64(strData[18])<<16 |
			uint64(strData[19])<<24 | uint64(strData[20])<<32 | uint64(strData[21])<<40 |
			uint64(strData[22])<<48 | uint64(strData[23])<<56
		if ptr == 0 {
			return "", nil
		}
		return ReadString(pid, ptr, 256)
	}

	length := int(strData[0] >> 1)
	if length > 22 {
		length = 22
	}
	if length == 0 {
		return "", nil
	}
	return string(strData[1 : 1+length]), nil
}

// UnlinkSoinfo removes the specified library from the linker's soinfo linked list.
func UnlinkSoinfo(pid int, payloadPath string, apiLevel int) error {
	offsets := GetSoinfoOffsets(apiLevel)

	linkerBase, err := GetModuleBase(pid, "linker64")
	if err != nil {
		return fmt.Errorf("cannot find linker64: %w", err)
	}

	// Find solist global variable using prefix match (handles LLVM suffixes)
	linkerPaths := []string{
		"/system/bin/linker64",
		"/apex/com.android.runtime/bin/linker64",
	}

	var solistAddr uint64
	for _, lpath := range linkerPaths {
		offset, name, err := FindSymbolOffsetPrefix(lpath, "__dl__ZL6solist")
		if err == nil {
			solistAddr = linkerBase + offset
			LogDebug("found solist symbol", "symbol", name, "addr", solistAddr)
			break
		}
	}

	if solistAddr == 0 {
		return fmt.Errorf("cannot locate solist symbol in linker64")
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

	var prevAddr uint64
	current := headPtr
	iterations := 0

	for current != 0 && iterations < 512 {
		iterations++

		path, err := readSoinfoRealpath(pid, current, offsets)
		if err != nil {
			// skip unreadable nodes
		} else if path != "" && strings.Contains(path, payloadPath) {
			LogInfo("found payload soinfo node", "addr", current, "path", path)

			targetNext, err := ReadPointer(pid, current+uint64(offsets.Next))
			if err != nil {
				return fmt.Errorf("cannot read target next pointer: %w", err)
			}

			if prevAddr == 0 {
				if err := WritePointer(pid, solistAddr, targetNext); err != nil {
					return fmt.Errorf("failed to update solist head: %w", err)
				}
			} else {
				if err := WritePointer(pid, prevAddr, targetNext); err != nil {
					return fmt.Errorf("failed to patch prev->next: %w", err)
				}
			}

			LogInfo("soinfo unlinked successfully", "path", path)
			return nil
		}

		prevAddr = current + uint64(offsets.Next)
		current, err = ReadPointer(pid, prevAddr)
		if err != nil {
			return fmt.Errorf("cannot read next pointer at %#x: %w", prevAddr, err)
		}
	}

	if iterations >= 512 {
		return fmt.Errorf("soinfo walk exceeded 512 iterations")
	}

	return fmt.Errorf("payload %q not found in soinfo list", payloadPath)
}
