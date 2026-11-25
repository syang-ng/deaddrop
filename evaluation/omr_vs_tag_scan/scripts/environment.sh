#!/usr/bin/env bash
# Records the hardware, software and code revisions the measurements ran on.
set -uo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
REPO=$(cd "$HERE/../.." && pwd)
echo "date: $(date -Is)"
echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
echo "logical_cpus: $(nproc)"
lscpu | grep -E '^(Thread\(s\) per core|Core\(s\) per socket|Socket\(s\)|Hypervisor vendor|Virtualization type|CPU max MHz|L3 cache)' | sed 's/  */ /g'
echo "cpu_mhz_now: $(grep -m1 'cpu MHz' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'n/a (VM)')"
free -g | awk '/Mem:|Swap:/ {print tolower($1) " total_gib=" $2}'
echo "os: $(. /etc/os-release && echo "$PRETTY_NAME") kernel $(uname -r)"
echo "pinning: none (no taskset/cpuset); OMR runs in Docker image omr-env:focal, Tag Scan on the host"
echo "git_head: $(git -C "$REPO" rev-parse HEAD) ($(git -C "$REPO" rev-parse --abbrev-ref HEAD))"
echo "git_uncommitted:"; git -C "$REPO" status --short | sed 's/^/  /'
echo "rustc: $(rustc --version)"; echo "cargo: $(cargo --version)"
echo "tag_scan crates:"; awk '/^name = "(x25519-dalek|curve25519-dalek|hkdf|hmac|sha2|subtle)"/ {n=$3; getline; print "  " n " " $3}' "$HERE/tag_scan/Cargo.lock" | tr -d '"'
echo "omr image (omr-env:focal):"
docker run --rm omr-env:focal bash -c 'g++ --version | head -1; cmake --version | head -1; cat /opt/src-versions.txt /opt/apt-versions.txt' | sed 's/^/  /'
echo "openssl x25519 reference (host, 1 core):"; openssl speed -seconds 3 ecdhx25519 2>/dev/null | tail -1 | sed 's/^/  /'
