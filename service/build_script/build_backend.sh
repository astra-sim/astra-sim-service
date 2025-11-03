#!/bin/bash
set -e

SCRIPT_DIR=$(dirname "$(realpath "$0")")

echo "Building backends sequentially... (logging to logs/)"

mkdir -p logs

BUILD_DIR="${SCRIPT_DIR}/../astra-sim/build"

cd "${BUILD_DIR}" || exit 1
echo "[INFO] Building Analytical..."
./astra_analytical/build.sh
echo "[DONE] Analytical build complete."
echo "[INFO] Waiting for all builds to complete..."

echo "[INFO] Building HTSim..."
echo "[INFO] Patching the HTSim build script first..."

cd "${BUILD_DIR}" || exit 1
./astra_htsim/build.sh
echo "[DONE] HTSIM build complete"
echo "[INFO] Waiting for all builds to complete..."

echo "[INFO] Building NS3..."
cd "${BUILD_DIR}" || exit 1
./astra_ns3/build.sh
echo "[DONE] NS3 build complete"

echo "All builds completed!"
