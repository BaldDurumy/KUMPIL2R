#!/usr/bin/env bash
set -e

echo "[*] Configuring & building KUMPIL2R..."
mkdir -p build
cd build
cmake -S .. -B . -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build . -j
echo "[*] Build Complete."
