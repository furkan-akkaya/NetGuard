#!/usr/bin/env bash
# Backward-compatible wrapper: experiment 01 now runs through the generic
# guarded runner, which carries every experiment (docs/LAB_SETUP.md).
exec bash "$(dirname "$0")/kali-run.sh" exp01-syn-scan
