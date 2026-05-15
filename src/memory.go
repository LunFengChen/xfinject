package main

import (
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
