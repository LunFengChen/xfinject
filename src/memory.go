package xfinject

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	pageSize          = 4096
	sysPidfdOpen      = 434
	sysProcessMadvise = 440
	madvDontNeed      = 4
)

type remoteIovec struct {
	Base uintptr
	Len  uintptr
}

var (
	ErrRemoteDiscardUnsupported = errors.New("remote private page discard unsupported")
	remoteDiscardUnsupported    bool
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

func pageAlignedRange(addr uint64, size int) (uint64, uint64) {
	start := addr &^ uint64(pageSize-1)
	end := (addr + uint64(size) + uint64(pageSize-1)) &^ uint64(pageSize-1)
	if end <= start {
		end = start + pageSize
	}
	return start, end - start
}

// DiscardRemotePrivatePages drops the target process's private CoW pages for
// this file-backed range.  After we restore libandroid_runtime bytes, this
// removes the dirty anonymous trap page so later forks see a pristine mapping
// without requiring a device reboot.
func DiscardRemotePrivatePages(pid int, addr uint64, size int) error {
	if remoteDiscardUnsupported {
		return ErrRemoteDiscardUnsupported
	}

	start, length := pageAlignedRange(addr, size)

	pidfd, _, errno := syscall.Syscall(sysPidfdOpen, uintptr(pid), 0, 0)
	if errno != 0 {
		if errno == syscall.ENOSYS {
			remoteDiscardUnsupported = true
			return fmt.Errorf("%w: pidfd_open", ErrRemoteDiscardUnsupported)
		}
		return fmt.Errorf("pidfd_open(%d): %w", pid, errno)
	}
	defer syscall.Close(int(pidfd))

	iov := remoteIovec{Base: uintptr(start), Len: uintptr(length)}
	n, _, errno := syscall.Syscall6(
		sysProcessMadvise,
		pidfd,
		uintptr(unsafe.Pointer(&iov)),
		1,
		madvDontNeed,
		0,
		0,
	)
	if errno != 0 {
		if errno == syscall.ENOSYS {
			remoteDiscardUnsupported = true
			return fmt.Errorf("%w: process_madvise", ErrRemoteDiscardUnsupported)
		}
		return fmt.Errorf("process_madvise(pid=%d range=%#x+%#x): %w", pid, start, length, errno)
	}
	if n < uintptr(length) {
		return fmt.Errorf("process_madvise(pid=%d range=%#x+%#x): short discard %#x", pid, start, length, n)
	}
	return nil
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
