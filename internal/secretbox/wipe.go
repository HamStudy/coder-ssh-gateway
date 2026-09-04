package secretbox

import "runtime"

// BestEffortWipe zeroes b in place.
//
// Honesty note per design section 22.5: Go does NOT guarantee complete
// erasure. The garbage collector may have copied the buffer, and prior
// string conversions or interface boxing leave unreachable copies behind.
// This function only scrubs the referenced backing array; treat process
// memory access as credential compromise regardless.
func BestEffortWipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
