#!/bin/sh
# Sleeps well past the manifest's 100ms timeout. The host must kill it and
# report a timeout, not block the scan.
sleep 5
echo '{"findings":[]}'
