package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type MapRange struct {
	Start uint64
	End   uint64
	Perms string
	Path  string
}

func ParseMaps(pid int) ([]MapRange, error) {
	path := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ranges []MapRange
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		addrRange := strings.Split(fields[0], "-")
		if len(addrRange) != 2 {
			continue
		}

		start, _ := strconv.ParseUint(addrRange[0], 16, 64)
		end, _ := strconv.ParseUint(addrRange[1], 16, 64)
		perms := fields[1]

		mapPath := ""
		if len(fields) >= 6 {
			mapPath = fields[5]
		}

		ranges = append(ranges, MapRange{
			Start: start,
			End:   end,
			Perms: perms,
			Path:  mapPath,
		})
	}

	return ranges, scanner.Err()
}

func GetModuleBase(pid int, moduleName string) (uint64, error) {
	ranges, err := ParseMaps(pid)
	if err != nil {
		return 0, err
	}

	for _, r := range ranges {
		if strings.Contains(r.Path, moduleName) {
			return r.Start, nil
		}
	}

	return 0, fmt.Errorf("module %s not found in pid %d", moduleName, pid)
}

func GetModuleRWSegment(pid int, moduleName string) (uint64, error) {
	ranges, err := ParseMaps(pid)
	if err != nil {
		return 0, err
	}

	for _, r := range ranges {
		if strings.Contains(r.Path, moduleName) && strings.Contains(r.Perms, "rw") {
			return r.Start, nil
		}
	}

	return 0, fmt.Errorf("rw segment for %s not found in pid %d", moduleName, pid)
}
