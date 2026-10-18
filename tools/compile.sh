#!/bin/bash
# compile.sh — runs INSIDE the asmb4-fwbuild container (arm toolchain + cramfs tools).
# Expects: /w/work/root.cramfs, /w/work/www.cramfs (from extract_ima.py)
#          /w/src/spa.inc (from gen_spa.py), /w/overlay/, /w/src/
# Produces: /w/work/root_new.cramfs, /w/work/www_new.cramfs
set -e
cd /tmp
rm -rf build && mkdir build
cd build

# unpack the stock partitions (fsck.cramfs preserves modes+symlinks on ext4)
fsck.cramfs --extract=/tmp/build/root /w/work/root.cramfs
fsck.cramfs --extract=/tmp/build/www  /w/work/www.cramfs

# merge our overlay (inittab entries, init.d scripts, webgo8080.sh, login.asp)
cp -a /w/overlay/root/. root/
cp /w/overlay/www/login.asp www/login.asp

# --- build the three custom binaries ---
arm-linux-gnueabi-gcc -Os -static -nostdlib -fno-builtin -fno-stack-protector \
    -o root/usr/local/bin/bmcweb /w/src/bmcweb.c
# bindhook: the card's ancient ld.so (glibc 2.3.2) cannot resolve gnu.hash-only
# DSOs -> --hash-style=both is MANDATORY, not optional.
arm-linux-gnueabi-gcc -Os -shared -nostdlib -fPIC -Wl,--hash-style=both \
    -o root/usr/local/lib/bindhook.so /w/src/bindhook.c
arm-linux-gnueabi-gcc -Os -static -nostdlib -fno-builtin -fno-stack-protector \
    -o root/usr/local/bin/kvmproxy /w/src/kvmproxy.c

chmod 755 root/usr/local/bin/bmcweb root/usr/local/bin/kvmproxy \
          root/usr/local/bin/webgo8080.sh root/usr/local/lib/bindhook.so \
          root/etc/init.d/bmcweb root/etc/init.d/kvmproxy
for r in rc2 rc3 rc4 rc5; do
    ln -sf ../init.d/kvmproxy root/etc/$r.d/S95kvmproxy
done

# repack partitions
mkfs.cramfs root /w/work/root_new.cramfs
mkfs.cramfs www  /w/work/www_new.cramfs
echo "[+] wrote work/root_new.cramfs + work/www_new.cramfs"
