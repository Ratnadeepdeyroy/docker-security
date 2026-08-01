//go:build !linux

package runtime

// NewEBPFSource is unavailable off Linux: eBPF is a Linux-kernel facility. The
// daemon falls back to the /proc source (also unsupported off Linux) or offline
// replay. Keeping this stub here means the scanner binary and any non-Linux
// build never reference github.com/cilium/ebpf.
func NewEBPFSource(cfg LiveConfig, resolver *ContainerResolver) (EventSource, error) {
	return nil, ErrLiveUnsupported
}
