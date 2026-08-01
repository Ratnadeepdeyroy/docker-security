//go:build linux && !arm64

package runtime

// goArchARM64 is false on non-arm64 Linux (amd64), selecting amd64 syscall
// numbers in the live sensor.
const goArchARM64 = false
