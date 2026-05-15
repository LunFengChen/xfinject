package main

import (
	"debug/elf"
	"fmt"
	"os"
)

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

	// Try dynamic symbols first (usually what we want for shared libs)
	symbols, err := ef.DynamicSymbols()
	if err == nil {
		for _, sym := range symbols {
			if sym.Name == symbolName {
				return sym.Value, nil
			}
		}
	}

	// Fallback to regular symbols
	symbols, err = ef.Symbols()
	if err == nil {
		for _, sym := range symbols {
			if sym.Name == symbolName {
				return sym.Value, nil
			}
		}
	}

	return 0, fmt.Errorf("symbol %s not found in %s", symbolName, libPath)
}

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
