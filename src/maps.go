package xfinject

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// MapRange is one entry from /proc/<pid>/maps.
type MapRange struct {
	Start  uint64
	End    uint64
	Offset uint64
	Perms  string
	Path   string
}

// ParseMaps reads and parses /proc/<pid>/maps. Hidden VMAs (via /proc/vma_hide)
// are transparently filtered out by the kernel; callers see what the target
// process itself would see in /proc/self/maps.
func ParseMaps(pid int) ([]MapRange, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ranges []MapRange
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		addr := strings.Split(fields[0], "-")
		if len(addr) != 2 {
			continue
		}
		start, _ := strconv.ParseUint(addr[0], 16, 64)
		end, _ := strconv.ParseUint(addr[1], 16, 64)
		path := ""
		if len(fields) >= 6 {
			path = fields[5]
		}
		offset, _ := strconv.ParseUint(fields[2], 16, 64)
		ranges = append(ranges, MapRange{Start: start, End: end, Offset: offset, Perms: fields[1], Path: path})
	}
	return ranges, scanner.Err()
}

// GetModuleBase returns the ELF load base of the named module (substring match).
//
// Android can expose non-load aliases before the real executable/private mapping
// (for example a zygote r--s libandroid_runtime.so mapping on Pixel 5 / Android
// 13).  Returning that first line makes symbol resolution land in the wrong VMA
// and /proc/<pid>/mem writes fail with EIO.  Prefer executable mappings and
// compute load base as start-file_offset; fall back to the first candidate only
// for unusual modules without an executable range.
func GetModuleBase(pid int, moduleName string) (uint64, error) {
	ranges, err := ParseMaps(pid)
	if err != nil {
		return 0, err
	}
	var fallback uint64
	for _, r := range ranges {
		if !strings.Contains(r.Path, moduleName) {
			continue
		}
		base := r.Start - r.Offset
		if fallback == 0 {
			fallback = base
		}
		if len(r.Perms) >= 3 && r.Perms[2] == 'x' {
			return base, nil
		}
	}
	if fallback != 0 {
		return fallback, nil
	}
	return 0, fmt.Errorf("module %s not found in pid %d", moduleName, pid)
}
