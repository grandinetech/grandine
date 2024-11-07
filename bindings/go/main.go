package grandine

/*
#cgo LDFLAGS: -L${SRCDIR}/lib -lc_grandine -lm -lz -ldl -lstdc++
#include "./lib/c_grandine.h"
*/
import "C"
import "unsafe"

func RunGrandine(args []string) {
	cargs := C.malloc(C.size_t(len(args)) * C.size_t(unsafe.Sizeof(uintptr(0))))

	a := (*[1<<30 - 1]*C.char)(cargs)

	for idx, arg := range args {
		a[idx] = C.CString(arg)
		defer C.free(unsafe.Pointer(a[idx]))
	}

	C.grandine_run(C.ulong(len(args)), (**C.char)(cargs))
}
