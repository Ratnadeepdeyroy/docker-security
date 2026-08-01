package harden

import (
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- GPU / accelerator isolation checks --------------------------------------
//
// AI/ML workloads run on GPUs, and the GPU is a genuinely under-served isolation
// surface: nvidia-container-toolkit is simultaneously required to expose a GPU
// and a repeated container-escape vector (the "Leaky Vessels" class,
// CVE-2024-0132 et al.), and GPUs shared across tenants (MIG/vGPU/time-slicing)
// have historically leaked residual device memory between users. Incumbent
// container scanners barely look here; these two checks make it first class.
//
// Both are advisory (INFO/low) by design — a GPU workload is not a
// misconfiguration, it just carries risks the operator must have consciously
// accepted — but they only fire when an accelerator is actually exposed.

// acceleratorDevicePrefixes are the character-device paths that expose a GPU or
// other accelerator to a container.
var acceleratorDevicePrefixes = []string{
	"/dev/nvidia", // NVIDIA (nvidia0, nvidiactl, nvidia-uvm, nvidia-modeset)
	"/dev/dri",    // AMD/Intel DRM render nodes
	"/dev/kfd",    // AMD ROCm compute
	"/dev/accel",  // Habana / generic accelerators
}

// gpuExposure summarises how (and whether) a workload can reach an accelerator.
type gpuExposure struct {
	present    bool
	devices    []string // matched device paths
	visibleAll bool     // NVIDIA_VISIBLE_DEVICES=all (every host GPU)
}

// detectGPU inspects devices, mounts and env for accelerator exposure.
func detectGPU(w *Workload) gpuExposure {
	var e gpuExposure
	add := func(p string) {
		for _, pre := range acceleratorDevicePrefixes {
			if strings.HasPrefix(p, pre) {
				e.present = true
				e.devices = append(e.devices, p)
				return
			}
		}
	}
	for _, d := range w.Devices {
		add(d.Path)
	}
	for _, m := range w.Mounts {
		add(strings.TrimSpace(m.Source))
		add(strings.TrimSpace(m.Destination))
	}
	if v, ok := w.Env["NVIDIA_VISIBLE_DEVICES"]; ok {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "", "void", "none":
			// no GPU requested
		case "all":
			e.present = true
			e.visibleAll = true
		default:
			e.present = true
		}
	}
	e.devices = dedupeSort(e.devices)
	return e
}

func checkGPUDevices(w *Workload) []Result {
	gpu := detectGPU(w)
	if !gpu.present {
		return nil
	}
	c := Control{
		ID:       "DS-RAT-BOX-017",
		Title:    "GPU/accelerator exposed — device-plugin escape surface",
		Severity: engine.SeverityMedium,
		Remediation: "Scope NVIDIA_VISIBLE_DEVICES to specific device UUIDs (never \"all\"); pin and " +
			"patch nvidia-container-toolkit (Leaky Vessels, CVE-2024-0132); expose only the required " +
			"/dev/nvidia* nodes via the device plugin, not a blanket /dev mount.",
		References: []string{"NIST SP 800-190 4.5.2", "MITRE ATT&CK T1610", "CVE-2024-0132"},
	}
	if gpu.visibleAll {
		return fail(c, w.Name, "NVIDIA_VISIBLE_DEVICES=all exposes every GPU on the host to this container; scope it to specific device UUIDs")
	}
	dev := strings.Join(gpu.devices, ", ")
	if dev == "" {
		dev = "requested via device plugin"
	}
	return info(c, w.Name, "accelerator exposed ("+dev+"): ensure nvidia-container-toolkit is patched and devices are scoped, as the toolkit is a known container-escape vector")
}

func checkGPUSharing(w *Workload) []Result {
	gpu := detectGPU(w)
	if !gpu.present {
		return nil
	}
	c := Control{
		ID:       "DS-RAT-BOX-018",
		Title:    "Multi-tenant GPU sharing — co-tenancy side-channel risk",
		Severity: engine.SeverityMedium,
		Remediation: "For multi-tenant GPUs, partition with MIG (hardware-isolated instances) rather " +
			"than time-slicing/vGPU; dedicate a GPU per trust boundary for sensitive workloads; ensure " +
			"device memory is scrubbed between tenants to prevent residual-data and side-channel leakage.",
		References: []string{"NIST SP 800-190 4.5.4", "MITRE ATT&CK T1610", "MITRE ATT&CK T1005"},
	}
	return info(c, w.Name, "GPU exposed to a workload: if this accelerator is shared across tenants via time-slicing or vGPU, device memory and transient-execution state can leak between co-tenants — prefer MIG or a dedicated GPU")
}
