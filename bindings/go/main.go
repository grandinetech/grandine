package grandine

/*
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -lc_grandine -lm -ldl
#include "../c/build/c_grandine.h"
*/
import "C"

func RunGrandine() {
	C.grandine_run()
}
