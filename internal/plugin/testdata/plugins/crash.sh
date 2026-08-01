#!/bin/sh
# Simulates a broken plugin: write to stderr and exit non-zero. The host must
# contain this as a module error, never a crash of the engine.
echo "intentional plugin crash" >&2
exit 1
