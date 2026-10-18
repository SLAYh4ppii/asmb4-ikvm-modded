#!/usr/bin/env bash
# build.sh — full pipeline: stock .ima -> modded KCMA8214_mod.ima
# usage: ./build.sh path/to/KCMA8214.ima
set -e
IMG=${1:?usage: ./build.sh <stock.ima>}
IMG=$(realpath "$IMG")

docker build -t asmb4-fwbuild .

mkdir -p work
python3 tools/extract_ima.py "$IMG" work/
python3 tools/gen_spa.py
docker run --rm -v "$PWD:/w" asmb4-fwbuild bash /w/tools/compile.sh
python3 tools/pack_ima.py "$IMG" work/KCMA8214_mod.ima \
    --module root work/root_new.cramfs --module www work/www_new.cramfs

echo
echo "DONE -> work/KCMA8214_mod.ima"
echo "flash: python3 tools/flash_image.py <BMC_IP> work/KCMA8214_mod.ima 8080 --flash"
