package xfinject

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

// vmaHideProcPath is the kernel module's control file. Its presence is what the
// "auto" mode autodetects.
const vmaHideProcPath = "/proc/vma_hide"

// vmaHideActive gates every /proc/vma_hide interaction. Resolved once at startup
// by SetVmaHideMode from the --vma-hide flag. When false, hideVma and
// clearHiddenVmasForUID are silent no-ops and the injector leaves the payload's
// VMAs visible in /proc/<pid>/maps (soinfo unlinking still happens — it is
// independent of the kernel module).
var vmaHideActive bool

// vmaHideStrict records that the operator passed --vma-hide=always, i.e. demanded
// hiding rather than best-effort. Under strict mode a hide failure is reported
// loudly (Error) instead of as an informational degrade, because the operator's
// stealth assumption no longer holds.
var vmaHideStrict bool

// VmaHideUsable reports whether /proc/vma_hide hiding is currently active, so
// callers can skip the work and the (otherwise misleading) "hidden" logging.
func VmaHideUsable() bool { return vmaHideActive }

// VmaHideStrict reports whether hiding was explicitly demanded (--vma-hide=always),
// so the caller can treat degraded hiding as an error rather than a soft notice.
func VmaHideStrict() bool { return vmaHideStrict }

// SetVmaHideMode resolves the --vma-hide mode and records whether the injector
// will use the kernel module: "never" forces it off, "always" forces it on, and
// "auto" (the default, also used for an unrecognized value) enables it only when
// /proc/vma_hide exists. It never fails — under "always" with the module absent,
// the later writes just warn rather than aborting the injection.
func SetVmaHideMode(mode string) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "never":
		vmaHideActive = false
		logger.Info("vma_hide", "mode", "never", "active", false)
	case "always":
		vmaHideActive = true
		vmaHideStrict = true
		logger.Info("vma_hide", "mode", "always", "active", true)
	default: // "auto" (and any unexpected value)
		if mode != "" && mode != "auto" {
			logger.Warn("unknown --vma-hide value, falling back to auto", "value", mode)
		}
		_, err := os.Stat(vmaHideProcPath)
		vmaHideActive = err == nil
		logger.Info("vma_hide", "mode", "auto", "active", vmaHideActive)
	}
}

// hideVma adds a per-UID hide entry to /proc/vma_hide. The kernel module
// filters this range out of /proc/<pid>/maps and /proc/<pid>/smaps for any
// process running as `uid`. Root (uid 0) is never filtered, so the injector
// itself still sees the live mapping. A no-op (returns nil) when vma_hide is
// inactive, so it never touches the file under --vma-hide=never.
//
// The wildcard "add 0x<s> 0x<e>" form (no uid) is kept by the kernel for
// backward compatibility, but every xfinject call uses the explicit-uid
// form so concurrent injections into different apps don't trample.
func hideVma(uid int, base uint64, end uint64) error {
	if !vmaHideActive {
		return nil
	}
	f, err := os.OpenFile(vmaHideProcPath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", vmaHideProcPath, err)
	}
	defer f.Close()
	if _, err = fmt.Fprintf(f, "add %d 0x%x 0x%x\n", uid, base, end); err != nil {
		return fmt.Errorf("write %s: %w", vmaHideProcPath, err)
	}
	return nil
}

// clearHiddenVmasForUID wipes only the entries belonging to one app UID.
// Called once at the start of each injection so stale entries from a previous
// run into the same app don't shadow the new run's mappings. With the new
// per-UID kernel module this is correctness-optional (the injector reads as
// root and is never filtered) but still useful for tidiness across multiple
// injections. A no-op when vma_hide is inactive.
func clearHiddenVmasForUID(uid int) error {
	if !vmaHideActive {
		return nil
	}
	f, err := os.OpenFile(vmaHideProcPath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", vmaHideProcPath, err)
	}
	defer f.Close()
	if _, err = fmt.Fprintf(f, "clear %d\n", uid); err != nil {
		return fmt.Errorf("clear %s: %w", vmaHideProcPath, err)
	}
	return nil
}

// SoinfoHideResult reports what UnlinkSoinfo accomplished for one payload, so the
// caller can render an accurate terminal status instead of an unconditional
// "cloaked". VmaActive mirrors whether /proc/vma_hide was in use this run; when
// false the payload's VMAs are intentionally left visible and VmaRanges/VmaHidden
// stay zero.
type SoinfoHideResult struct {
	Unlinked  bool // soinfo patched out of the linker solist
	VmaActive bool // /proc/vma_hide in use for this run
	VmaRanges int  // payload VMA ranges discovered
	VmaHidden int  // ranges successfully hidden (== VmaRanges on full success)
}

// FullyHidden reports that every discovered payload VMA was hidden. Trivially
// false when vma_hide is inactive (the payload is then deliberately visible).
func (r SoinfoHideResult) FullyHidden() bool {
	return r.VmaActive && r.VmaRanges > 0 && r.VmaHidden == r.VmaRanges
}

// UnlinkSoinfo finds the payload on the linker's solist, hides every VMA
// belonging to it (file-backed segments + linker guard pages + [anon:.bss])
// from the app's UID via /proc/vma_hide, then patches it out of the linked
// list so dl_iterate_phdr no longer sees it. The returned SoinfoHideResult lets
// the caller report honestly whether hiding fully succeeded; a returned error is
// a hard failure of the unlink itself (the payload could not be located/patched).
func UnlinkSoinfo(pid int, uid int, payloadPath string, apiLevel int) (SoinfoHideResult, error) {
	res := SoinfoHideResult{VmaActive: vmaHideActive}
	offsets := GetSoinfoOffsets(apiLevel)

	linkerBase, err := GetModuleBase(pid, "linker64")
	if err != nil {
		return res, fmt.Errorf("linker64 base: %w", err)
	}

	var solistAddr uint64
	var sonextAddr uint64
	for _, lpath := range []string{
		"/system/bin/linker64",
		"/apex/com.android.runtime/bin/linker64",
	} {
		if solistAddr == 0 {
			if off, name, err := FindSymbolOffsetPrefix(lpath, "__dl__ZL6solist"); err == nil {
				solistAddr = linkerBase + off
				logger.Debug("solist resolved", "symbol", name, "addr", solistAddr, "path", lpath)
			}
		}
		if sonextAddr == 0 {
			if off, name, err := FindSymbolOffsetPrefix(lpath, "__dl__ZL6sonext"); err == nil {
				sonextAddr = linkerBase + off
				logger.Debug("sonext resolved", "symbol", name, "addr", sonextAddr, "path", lpath)
			}
		}
		if solistAddr != 0 && sonextAddr != 0 {
			break
		}
	}
	if solistAddr == 0 {
		return res, fmt.Errorf("cannot locate solist in linker64")
	}
	if sonextAddr == 0 {
		logger.Warn("cannot locate sonext in linker64; tail unlink may leave future dlopen entries unreachable")
	}

	headPtr, err := ReadPointer(pid, solistAddr)
	if err != nil {
		return res, fmt.Errorf("read solist head: %w", err)
	}
	if headPtr == 0 {
		return res, fmt.Errorf("solist head is null")
	}

	logger.Debug("walking solist", "addr", headPtr)

	var prevAddr uint64
	var prevSoinfo uint64
	current := headPtr
	iterations := 0
	for current != 0 && iterations < 512 {
		iterations++

		path, err := readSoinfoRealpath(pid, current, offsets)
		if err == nil && path != "" && strings.Contains(path, payloadPath) {
			logger.Debug("payload soinfo found", "addr", current, "path", path)

			// VMA hiding is gated on the kernel module; when inactive we skip the
			// maps scan + hide entirely and only unlink the soinfo from the list.
			if vmaHideActive {
				vmaRanges, err := findPayloadVmaRanges(pid, payloadPath)
				if err != nil {
					logger.Warn("find payload VMA ranges failed", "error", err)
				}
				res.VmaRanges = len(vmaRanges)
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
				res.VmaHidden = hidden
				logger.Info("payload vmas hidden", "count", hidden, "of", res.VmaRanges, "base", vmaBase, "end", vmaEnd)
			}

			targetNext, err := ReadPointer(pid, current+uint64(offsets.Next))
			if err != nil {
				return res, fmt.Errorf("read target next: %w", err)
			}
			// bionic keeps both the list head (solist) and the tail pointer
			// (sonext).  If the payload is currently the tail, only patching
			// prev->next leaves sonext dangling at the orphaned payload.  A later
			// app dlopen then appends new soinfos behind that orphan, making them
			// unreachable from solist; their eventual dlclose aborts with
			// "soinfo is not in soinfo_list (double unload?)".
			if sonextAddr != 0 {
				sonext, err := ReadPointer(pid, sonextAddr)
				if err != nil {
					logger.Warn("read sonext failed", "error", err)
				} else if sonext == current {
					if err := WritePointer(pid, sonextAddr, prevSoinfo); err != nil {
						return res, fmt.Errorf("patch sonext tail: %w", err)
					}
					logger.Debug("sonext retargeted", "old", current, "new", prevSoinfo)
				}
			}
			if prevAddr == 0 {
				if err := WritePointer(pid, solistAddr, targetNext); err != nil {
					return res, fmt.Errorf("patch solist head: %w", err)
				}
			} else {
				if err := WritePointer(pid, prevAddr, targetNext); err != nil {
					return res, fmt.Errorf("patch prev->next: %w", err)
				}
			}
			res.Unlinked = true
			logger.Info("soinfo unlinked", "path", path)
			return res, nil
		}

		prevSoinfo = current
		prevAddr = current + uint64(offsets.Next)
		current, err = ReadPointer(pid, prevAddr)
		if err != nil {
			return res, fmt.Errorf("read next pointer at %#x: %w", prevAddr, err)
		}
	}

	if iterations >= 512 {
		return res, fmt.Errorf("soinfo walk exceeded %d iterations", iterations)
	}
	return res, fmt.Errorf("payload %q not in soinfo list", payloadPath)
}
