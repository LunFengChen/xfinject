package main

import (
	"fmt"
	"os"
	"strings"
)

// SoinfoOffsets holds version-specific offsets into the linker's soinfo struct.
// `Next` is stable across API levels (since at least API 26). `Realpath` is the
// API-level-dependent offset of `std::string realpath_` and must be a starting
// guess — the actual probe in readSoinfoRealpath scans a small window around
// it for a plausible decoded string.
type SoinfoOffsets struct {
	Next     int
	Realpath int
}

// GetSoinfoOffsets returns the best-guess realpath offset for the given API
// level. The walker scans nearby offsets if the guess decodes nonsense, so
// these don't have to be exact.
func GetSoinfoOffsets(apiLevel int) SoinfoOffsets {
	switch {
	case apiLevel >= 33:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x1A0}
	case apiLevel >= 31:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x198}
	case apiLevel >= 30:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x190}
	case apiLevel >= 29:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x188}
	default:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x180}
	}
}

// realpathCandidateOffsets returns the offsets to try when probing for the
// realpath std::string. The struct layout has drifted by ±8 between minor
// AOSP releases, so we try a small window centered on the canonical offset
// for the API.
func realpathCandidateOffsets(base int) []int {
	return []int{base, base + 8, base - 8, base + 16, base - 16}
}

// readSoinfoRealpath decodes the libc++ std::string realpath field. libc++
// SSO encodes either a short string (inline up to 22 bytes) or a long string
// (8-byte capacity + 8-byte size + 8-byte ptr). Bit 0 of the first byte
// selects the layout.
//
// The Realpath offset has drifted across AOSP versions, so we try a small
// window of candidates and return the first that decodes to a path-like
// string (starts with '/'). Returns "" if no offset yields a plausible path.
func readSoinfoRealpath(pid int, soinfoAddr uint64, offsets SoinfoOffsets) (string, error) {
	var lastErr error
	for _, off := range realpathCandidateOffsets(offsets.Realpath) {
		s, err := decodeStdString(pid, soinfoAddr+uint64(off))
		if err != nil {
			lastErr = err
			continue
		}
		if len(s) > 0 && s[0] == '/' {
			return s, nil
		}
	}
	return "", lastErr
}

func decodeStdString(pid int, addr uint64) (string, error) {
	strData, err := ReadMem(pid, addr, 32)
	if err != nil {
		return "", err
	}
	if strData[0]&1 != 0 {
		ptr := uint64(strData[16]) | uint64(strData[17])<<8 | uint64(strData[18])<<16 |
			uint64(strData[19])<<24 | uint64(strData[20])<<32 | uint64(strData[21])<<40 |
			uint64(strData[22])<<48 | uint64(strData[23])<<56
		if ptr == 0 {
			return "", nil
		}
		return ReadString(pid, ptr, 256)
	}
	length := min(int(strData[0]>>1), 22)
	if length == 0 {
		return "", nil
	}
	return string(strData[1 : 1+length]), nil
}

type SoinfoVmaInfo struct {
	Addr uint64 // soinfo node address
	Base uint64 // load address (page-aligned, first VMA start)
	End  uint64 // last mapped byte+1 (last VMA end)
}

type payloadVmaRange struct {
	Start uint64
	End   uint64
	Perms string
	Path  string
}

// findPayloadVmaRanges returns every VMA belonging to the loaded payload:
// the three file-backed PT_LOAD segments and the linker's adjacent satellite
// mappings (PROT_NONE guards from the initial reservation, and the
// [anon:.bss] tail of the last LOAD whose memsz > filesz). All of these are
// dead giveaways of which library was loaded; we hide them together.
func findPayloadVmaRanges(pid int, payloadPath string) ([]payloadVmaRange, error) {
	ranges, err := ParseMaps(pid)
	if err != nil {
		return nil, fmt.Errorf("parse maps: %w", err)
	}
	var result []payloadVmaRange
	for _, r := range ranges {
		if r.Path != "" && strings.Contains(r.Path, payloadPath) {
			result = append(result, payloadVmaRange{Start: r.Start, End: r.End, Perms: r.Perms, Path: r.Path})
			logger.Debug("payload segment", "start", r.Start, "end", r.End, "perms", r.Perms)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("payload path %q not found in maps", payloadPath)
	}

	// Fixed-point: pick up any guard / .bss VMA whose boundary touches a known
	// payload boundary, then extend the boundary set and repeat.
	boundary := make(map[uint64]bool)
	added := make(map[[2]uint64]bool)
	for _, r := range result {
		boundary[r.Start] = true
		boundary[r.End] = true
		added[[2]uint64{r.Start, r.End}] = true
	}
	for {
		grew := false
		for _, r := range ranges {
			key := [2]uint64{r.Start, r.End}
			if added[key] {
				continue
			}
			isGuard := r.Perms == "---p" && r.Path == ""
			isBss := r.Path == "[anon:.bss]"
			if !isGuard && !isBss {
				continue
			}
			if !boundary[r.Start] && !boundary[r.End] {
				continue
			}
			result = append(result, payloadVmaRange{Start: r.Start, End: r.End, Perms: r.Perms, Path: r.Path})
			logger.Debug("payload satellite", "start", r.Start, "end", r.End, "perms", r.Perms, "path", r.Path)
			boundary[r.Start] = true
			boundary[r.End] = true
			added[key] = true
			grew = true
		}
		if !grew {
			break
		}
	}
	return result, nil
}

// hideVma adds a per-UID hide entry to /proc/vma_hide. The kernel module
// filters this range out of /proc/<pid>/maps and /proc/<pid>/smaps for any
// process running as `uid`. Root (uid 0) is never filtered, so the injector
// itself still sees the live mapping.
//
// The wildcard "add 0x<s> 0x<e>" form (no uid) is kept by the kernel for
// backward compatibility, but every gozinject call uses the explicit-uid
// form so concurrent injections into different apps don't trample.
func hideVma(uid int, base uint64, end uint64) error {
	f, err := os.OpenFile("/proc/vma_hide", os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open /proc/vma_hide: %w", err)
	}
	defer f.Close()
	if _, err = fmt.Fprintf(f, "add %d 0x%x 0x%x\n", uid, base, end); err != nil {
		return fmt.Errorf("write /proc/vma_hide: %w", err)
	}
	return nil
}

// clearHiddenVmasForUID wipes only the entries belonging to one app UID.
// Called once at the start of each injection so stale entries from a previous
// run into the same app don't shadow the new run's mappings. With the new
// per-UID kernel module this is correctness-optional (the injector reads as
// root and is never filtered) but still useful for tidiness across multiple
// injections.
func clearHiddenVmasForUID(uid int) error {
	f, err := os.OpenFile("/proc/vma_hide", os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open /proc/vma_hide: %w", err)
	}
	defer f.Close()
	if _, err = fmt.Fprintf(f, "clear %d\n", uid); err != nil {
		return fmt.Errorf("clear /proc/vma_hide: %w", err)
	}
	return nil
}

// UnlinkSoinfo finds the payload on the linker's solist, hides every VMA
// belonging to it (file-backed segments + linker guard pages + [anon:.bss])
// from the app's UID via /proc/vma_hide, then patches it out of the linked
// list so dl_iterate_phdr no longer sees it.
func UnlinkSoinfo(pid int, uid int, payloadPath string, apiLevel int) (*SoinfoVmaInfo, error) {
	offsets := GetSoinfoOffsets(apiLevel)

	linkerBase, err := GetModuleBase(pid, "linker64")
	if err != nil {
		return nil, fmt.Errorf("linker64 base: %w", err)
	}

	var solistAddr uint64
	for _, lpath := range []string{
		"/system/bin/linker64",
		"/apex/com.android.runtime/bin/linker64",
	} {
		if off, name, err := FindSymbolOffsetPrefix(lpath, "__dl__ZL6solist"); err == nil {
			solistAddr = linkerBase + off
			logger.Debug("solist resolved", "symbol", name, "addr", solistAddr, "path", lpath)
			break
		}
	}
	if solistAddr == 0 {
		return nil, fmt.Errorf("cannot locate solist in linker64")
	}

	headPtr, err := ReadPointer(pid, solistAddr)
	if err != nil {
		return nil, fmt.Errorf("read solist head: %w", err)
	}
	if headPtr == 0 {
		return nil, fmt.Errorf("solist head is null")
	}

	logger.Debug("walking solist", "addr", headPtr)

	var prevAddr uint64
	current := headPtr
	iterations := 0
	for current != 0 && iterations < 512 {
		iterations++

		path, err := readSoinfoRealpath(pid, current, offsets)
		if err == nil && path != "" && strings.Contains(path, payloadPath) {
			logger.Debug("payload soinfo found", "addr", current, "path", path)

			vmaRanges, err := findPayloadVmaRanges(pid, payloadPath)
			if err != nil {
				logger.Warn("find payload VMA ranges failed", "error", err)
			}
			var vmaBase, vmaEnd uint64
			hidden := 0
			for _, vr := range vmaRanges {
				if vmaBase == 0 || vr.Start < vmaBase {
					vmaBase = vr.Start
				}
				if vr.End > vmaEnd {
					vmaEnd = vr.End
				}
				if err := hideVma(uid, vr.Start, vr.End); err != nil {
					logger.Warn("vma_hide failed", "start", vr.Start, "end", vr.End, "error", err)
				} else {
					logger.Debug("vma hidden", "start", vr.Start, "end", vr.End, "perms", vr.Perms)
					hidden++
				}
			}
			logger.Info("payload vmas hidden", "count", hidden, "base", vmaBase, "end", vmaEnd)
			vmaInfo := &SoinfoVmaInfo{Addr: current, Base: vmaBase, End: vmaEnd}

			targetNext, err := ReadPointer(pid, current+uint64(offsets.Next))
			if err != nil {
				return vmaInfo, fmt.Errorf("read target next: %w", err)
			}
			if prevAddr == 0 {
				if err := WritePointer(pid, solistAddr, targetNext); err != nil {
					return vmaInfo, fmt.Errorf("patch solist head: %w", err)
				}
			} else {
				if err := WritePointer(pid, prevAddr, targetNext); err != nil {
					return vmaInfo, fmt.Errorf("patch prev->next: %w", err)
				}
			}
			logger.Info("soinfo unlinked", "path", path)
			return vmaInfo, nil
		}

		prevAddr = current + uint64(offsets.Next)
		current, err = ReadPointer(pid, prevAddr)
		if err != nil {
			return nil, fmt.Errorf("read next pointer at %#x: %w", prevAddr, err)
		}
	}

	if iterations >= 512 {
		return nil, fmt.Errorf("soinfo walk exceeded %d iterations", iterations)
	}
	return nil, fmt.Errorf("payload %q not in soinfo list", payloadPath)
}
