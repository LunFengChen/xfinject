package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"

	"github.com/LunFengChen/xfinject/src"
)

//export xf_inject_by_package
func xf_inject_by_package(cPkg *C.char, cPayload *C.char) C.int {
	if cPkg == nil || cPayload == nil {
		return -2
	}
	pkg := C.GoString(cPkg)
	payload := C.GoString(cPayload)
	_, err := xfinject.InjectByPackage(pkg, []string{payload})
	if err != nil {
		return -1
	}
	return 0
}

//export xf_inject_payloads_by_package
func xf_inject_payloads_by_package(cPkg *C.char, cPayloads **C.char, count C.int) C.int {
	if cPkg == nil || cPayloads == nil || count <= 0 {
		return -2
	}
	pkg := C.GoString(cPkg)
	payloads := make([]string, 0, int(count))
	base := unsafe.Pointer(cPayloads)
	ptrs := unsafe.Slice((**C.char)(base), int(count))
	for _, p := range ptrs {
		if p == nil {
			return -2
		}
		payloads = append(payloads, C.GoString(p))
	}
	_, err := xfinject.InjectByPackage(pkg, payloads)
	if err != nil {
		return -1
	}
	return 0
}

//export xf_inject_request_json
func xf_inject_request_json(cRequestJSON *C.char, cAllowlistPath *C.char) C.int {
	if cRequestJSON == nil {
		return -2
	}
	var allow *xfinject.Allowlist
	if cAllowlistPath != nil {
		path := C.GoString(cAllowlistPath)
		if path != "" {
			loaded, err := xfinject.LoadAllowlist(path)
			if err != nil {
				return -3
			}
			allow = loaded
		}
	}
	_, err := xfinject.RunRequestJSON([]byte(C.GoString(cRequestJSON)), allow)
	if err != nil {
		return -1
	}
	return 0
}

func main() {}
