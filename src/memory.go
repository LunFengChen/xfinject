package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

func WriteMem(pid int, addr uint64, data []byte) error {
	path := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteAt(data, int64(addr))
	return err
}

func ReadMem(pid int, addr uint64, size int) ([]byte, error) {
	path := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(path)
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

// ReadU32 reads a 32-bit little-endian value from process memory.
func ReadU32(pid int, addr uint64) (uint32, error) {
	data, err := ReadMem(pid, addr, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(data), nil
}

// WriteU32 writes a 32-bit little-endian value to process memory.
func WriteU32(pid int, addr uint64, val uint32) error {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, val)
	return WriteMem(pid, addr, buf)
}

// ZeroMem writes zeros to a region of process memory.
func ZeroMem(pid int, addr uint64, size int) error {
	return WriteMem(pid, addr, make([]byte, size))
}
