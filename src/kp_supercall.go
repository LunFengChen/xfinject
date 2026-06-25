package xfinject

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	kpSupercallNR       = 45
	kpMajor             = 0
	kpMinor             = 13
	kpPatch             = 2
	kpMagicTag          = 0x1158
	kpCmdHello          = 0x1000
	kpCmdKpmControl     = 0x1022
	kpCmdKpmList        = 0x1031
	kpHelloMagic        = 0x11581158
	kpDefaultModuleName = "xfvmahide"
	kpDefaultSuperkey   = "xiaofeng777"
)

func kpSuperkey() string {
	if v := strings.TrimSpace(os.Getenv("XFINJECT_KP_SUPERKEY")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("KP_SUPERKEY")); v != "" {
		return v
	}
	return kpDefaultSuperkey
}

func kpVerAndCmd(cmd uintptr) uintptr {
	versionCode := uintptr((kpMajor << 16) | (kpMinor << 8) | kpPatch)
	return (versionCode << 32) | (kpMagicTag << 16) | (cmd & 0xFFFF)
}

func kpBytePtr(s string) *byte {
	p, err := syscall.BytePtrFromString(s)
	if err != nil {
		return nil
	}
	return p
}

func kpSupercallRaw(key string, cmd uintptr, a1, a2, a3 uintptr) (uintptr, syscall.Errno) {
	keyp := kpBytePtr(key)
	if keyp == nil {
		return ^uintptr(0), syscall.EINVAL
	}
	r1, _, errno := syscall.Syscall6(kpSupercallNR, uintptr(unsafe.Pointer(keyp)), kpVerAndCmd(cmd), a1, a2, a3, 0)
	return r1, errno
}

func kpReady() bool {
	r1, errno := kpSupercallRaw(kpSuperkey(), kpCmdHello, 0, 0, 0)
	return errno == 0 && r1 == kpHelloMagic
}

func kpKpmList() (string, error) {
	buf := make([]byte, 4096)
	r1, errno := kpSupercallRaw(kpSuperkey(), kpCmdKpmList, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
	if errno != 0 {
		return "", fmt.Errorf("kpm list errno=%v", errno)
	}
	if int64(r1) < 0 {
		return "", fmt.Errorf("kpm list ret=%d", int64(r1))
	}
	// Like ctl0, the kernel writes the textual result into buf. Treat r1 only as
	// success/failure and recover the actual string by its trailing NUL.
	out := string(buf)
	if idx := strings.IndexByte(out, '\x00'); idx >= 0 {
		out = out[:idx]
	}
	return strings.TrimRight(out, "\x00\n"), nil
}

func kpKpmControl(name string, ctlArgs string) (string, error) {
	namep := kpBytePtr(name)
	argsp := kpBytePtr(ctlArgs)
	if namep == nil || argsp == nil {
		return "", fmt.Errorf("invalid kpm control args")
	}
	buf := make([]byte, 4096)
	r1, errno := kpSupercallRaw(kpSuperkey(), kpCmdKpmControl,
		uintptr(unsafe.Pointer(namep)),
		uintptr(unsafe.Pointer(argsp)),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if errno != 0 {
		return "", fmt.Errorf("kpm control errno=%v", errno)
	}
	if int64(r1) < 0 {
		return "", fmt.Errorf("kpm control ret=%d", int64(r1))
	}
	return strings.TrimRight(string(buf), "\x00\n"), nil
}

func kpXfvmahideAvailable() bool {
	if !kpReady() {
		return false
	}
	// Probe the exact module we need instead of relying on the generic KPM list
	// output shape. If ctl0("list") succeeds, xfvmahide is present and usable.
	_, err := kpKpmControl(kpDefaultModuleName, "list")
	return err == nil
}
