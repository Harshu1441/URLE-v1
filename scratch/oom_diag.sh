#!/bin/bash
set -e
CGPATH=/sys/fs/cgroup/ulre.slice/it-oom-debug

# Clean up any old run
rmdir "$CGPATH" 2>/dev/null || true
mkdir -p "$CGPATH"

# Enable memory controller in parent if needed
echo '+memory +pids' > /sys/fs/cgroup/ulre.slice/cgroup.subtree_control 2>/dev/null || true

# Set limits: 64MB max, 32MB high, disable swap
echo 67108864 > "$CGPATH/memory.max"
echo 33554432 > "$CGPATH/memory.high"
echo 0        > "$CGPATH/memory.swap.max" 2>/dev/null || true

# Start a hog: allocate and touch 40 MB of anonymous pages then hold
bash -c '
  buf=$(dd if=/dev/urandom bs=1024 count=40960 2>/dev/null | base64)
  sleep 10
' &
HOG=$!

sleep 0.5
echo "$HOG" > "$CGPATH/cgroup.procs" || { echo "cgroup.procs write failed"; kill $HOG; exit 1; }

echo "Hog PID: $HOG moved to cgroup"
sleep 3

echo "=== memory.current ==="
cat "$CGPATH/memory.current"
echo "=== memory.max ==="
cat "$CGPATH/memory.max"
echo "=== memory.high ==="
cat "$CGPATH/memory.high"
echo "=== memory.events ==="
cat "$CGPATH/memory.events" 2>/dev/null || echo "(no memory.events)"
echo "=== memory.stat (anon) ==="
grep -E '^anon|^file|^slab' "$CGPATH/memory.stat" 2>/dev/null || echo "(no memory.stat)"

kill "$HOG" 2>/dev/null
wait "$HOG" 2>/dev/null
rmdir "$CGPATH" 2>/dev/null || true
echo "DONE"
