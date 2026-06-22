package xfinject

import (
	"encoding/binary"
	"fmt"
	"os"
)

// WriteMem writes data into the target process's address space via /proc/<pid>/mem.
// Requires PTRACE_MODE_ATTACH_FSCREDS — caller must be root or already attached.
func WriteMem(pid int, addr uint64, data []byte) error {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", pid), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteAt(data, int64(addr))
	return err
}

// ReadMem reads `size` bytes from the target process's address space.
func ReadMem(pid int, addr uint64, size int) ([]byte, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data := make([]byte, size)
	_, err = f.ReadAt(data, int64(addr))
	return data, err
}

// ReadPointer reads a 64-bit little-endian pointer from process memory.
func ReadPointer(pid int, addr uint64) (uint64, error) {
	data, err := ReadMem(pid, addr, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data), nil
}

// WritePointer writes a 64-bit little-endian pointer to process memory.
func WritePointer(pid int, addr uint64, val uint64) error {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, val)
	return WriteMem(pid, addr, buf)
}

// ReadString reads a null-terminated string from process memory (up to maxLen bytes).
func ReadString(pid int, addr uint64, maxLen int) (string, error) {
	data, err := ReadMem(pid, addr, maxLen)
	if err != nil {
		return "", err
	}
	for i, b := range data {
		if b == 0 {
			return string(data[:i]), nil
		}
	}
	return string(data), nil
}
