package xfinject

import (
	"debug/elf"
	"fmt"
	"os"
	"strings"
)

// FindSymbolOffset returns the file/load offset of the named symbol.
// Searches dynamic symbols first, then the regular symbol table.
func FindSymbolOffset(libPath string, symbolName string) (uint64, error) {
	f, err := os.Open(libPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	ef, err := elf.NewFile(f)
	if err != nil {
		return 0, err
	}

	if symbols, err := ef.DynamicSymbols(); err == nil {
		for _, sym := range symbols {
			if sym.Name == symbolName {
				return sym.Value, nil
			}
		}
	}
	if symbols, err := ef.Symbols(); err == nil {
		for _, sym := range symbols {
			if sym.Name == symbolName {
				return sym.Value, nil
			}
		}
	}
	return 0, fmt.Errorf("symbol %s not found in %s", symbolName, libPath)
}

// FindSymbolOffsetPrefix finds a symbol by prefix match. Needed for LLVM-suffixed
// local symbols like "__dl__ZL6solist.llvm.XXXXX".
func FindSymbolOffsetPrefix(libPath string, prefix string) (uint64, string, error) {
	f, err := os.Open(libPath)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	ef, err := elf.NewFile(f)
	if err != nil {
		return 0, "", err
	}

	if symbols, err := ef.Symbols(); err == nil {
		for _, sym := range symbols {
			if strings.HasPrefix(sym.Name, prefix) && sym.Value != 0 {
				return sym.Value, sym.Name, nil
			}
		}
	}
	if symbols, err := ef.DynamicSymbols(); err == nil {
		for _, sym := range symbols {
			if strings.HasPrefix(sym.Name, prefix) && sym.Value != 0 {
				return sym.Value, sym.Name, nil
			}
		}
	}
	return 0, "", fmt.Errorf("symbol with prefix %s not found in %s", prefix, libPath)
}

// FindSymbolAddress resolves a symbol to its runtime address in the target process,
// by combining the module's load base (from /proc/<pid>/maps) with the symbol's
// file offset (from the on-disk ELF).
func FindSymbolAddress(pid int, libPath string, libName string, symbolName string) (uint64, error) {
	base, err := GetModuleBase(pid, libName)
	if err != nil {
		return 0, err
	}
	offset, err := FindSymbolOffset(libPath, symbolName)
	if err != nil {
		return 0, err
	}
	return base + offset, nil
}
