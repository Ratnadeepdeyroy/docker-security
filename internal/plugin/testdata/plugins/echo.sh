#!/bin/sh
# Reference docker-security plugin. Reads the JSON request from stdin (and
# discards it, so the host writer never gets SIGPIPE), then emits a single
# deterministic finding. Real plugins would parse the target and analyze it;
# this one proves the round trip end to end.
cat > /dev/null
cat <<'JSON'
{"findings":[{"rule_id":"DS-PLUGIN-ECHO-001","severity":"medium","title":"echo plugin finding","description":"contributed by the out-of-process echo plugin","resource":"demo","remediation":"none; this is a demonstration plugin","references":["https://example.com/echo-plugin"]}]}
JSON
