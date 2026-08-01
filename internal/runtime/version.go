package runtime

// RuleSetVersion identifies the built-in detection rule pack. It is stamped onto
// every detection and forensic bundle so an alert is traceable to the exact
// heuristics that produced it. Bump it whenever rule behavior changes.
const RuleSetVersion = "ds-rt-2026.07"

// SensorVersion is the sensor/core version, surfaced by `dsecrat-runtime version`.
const SensorVersion = "0.1.0"
