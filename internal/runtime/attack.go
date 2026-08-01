package runtime

// --- MITRE ATT&CK for Containers -----------------------------------------

// Technique is a MITRE ATT&CK technique the sensor maps detections to. Mapping
// every rule to ATT&CK is what turns a pile of alerts into a coverage story an
// analyst (or an agent) can reason about.
type Technique struct {
	ID     string // e.g. "T1611"
	Name   string // e.g. "Escape to Host"
	Tactic string // e.g. "Privilege Escalation"
	URL    string // canonical ATT&CK reference
}

// The technique set the built-in rules use. Kept as a small curated table
// rather than a full import of ATT&CK — we only reference what we detect, and
// each entry doubles as the finding's standard reference.
var (
	techEscapeToHost   = Technique{"T1611", "Escape to Host", "Privilege Escalation", "https://attack.mitre.org/techniques/T1611/"}
	techUnixShell      = Technique{"T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution", "https://attack.mitre.org/techniques/T1059/004/"}
	techIngressTool    = Technique{"T1105", "Ingress Tool Transfer", "Command and Control", "https://attack.mitre.org/techniques/T1105/"}
	techCloudIMDS      = Technique{"T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", "Credential Access", "https://attack.mitre.org/techniques/T1552/005/"}
	techUnsecuredCred  = Technique{"T1552", "Unsecured Credentials", "Credential Access", "https://attack.mitre.org/techniques/T1552/"}
	techStealToken     = Technique{"T1528", "Steal Application Access Token", "Credential Access", "https://attack.mitre.org/techniques/T1528/"}
	techResourceHijack = Technique{"T1496", "Resource Hijacking", "Impact", "https://attack.mitre.org/techniques/T1496/"}
	techAppLayerC2     = Technique{"T1071", "Application Layer Protocol", "Command and Control", "https://attack.mitre.org/techniques/T1071/"}
	techKernelModule   = Technique{"T1547.006", "Boot or Logon Autostart Execution: Kernel Modules and Extensions", "Persistence", "https://attack.mitre.org/techniques/T1547/006/"}
	techRootkit        = Technique{"T1014", "Rootkit", "Defense Evasion", "https://attack.mitre.org/techniques/T1014/"}
	techElevControl    = Technique{"T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", "https://attack.mitre.org/techniques/T1548/"}
	techPromptInject   = Technique{"T1059", "Command and Scripting Interpreter", "Execution", "https://attack.mitre.org/techniques/T1059/"}
	techHijackExecFlow = Technique{"T1574.006", "Hijack Execution Flow: Dynamic Linker Hijacking", "Persistence", "https://attack.mitre.org/techniques/T1574/006/"}
	techReflectiveLoad = Technique{"T1620", "Reflective Code Loading", "Defense Evasion", "https://attack.mitre.org/techniques/T1620/"}
)
