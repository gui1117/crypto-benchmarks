#!/bin/sh

# The ring operations are multi-threaded (`ark-vrf/parallel`), and that is intentional.
# What we do not want is the amount and placement of that parallelism varying between
# runs, so restrict the process to one hardware thread per *performance* core:
#
#   - On a hybrid CPU (Intel P/E cores) spreading over every logical CPU mixes fast and
#     slow cores, and the result then depends on how the scheduler placed the threads.
#   - This work is compute-bound, so SMT siblings add heat more than throughput, and
#     heat is what makes the numbers drift over a long run.
#
# Performance cores are identified as those in the highest max-frequency tier; one CPU
# is taken per distinct physical core. Falls back to no pinning if sysfs is unavailable.
pcore_cpu_list() {
    max=0
    for f in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/cpuinfo_max_freq; do
        [ -r "$f" ] || continue
        v=$(cat "$f")
        [ "$v" -gt "$max" ] && max=$v
    done
    [ "$max" -eq 0 ] && return 1

    seen=' '
    list=''
    for d in /sys/devices/system/cpu/cpu[0-9]*; do
        f=$d/cpufreq/cpuinfo_max_freq
        [ -r "$f" ] || continue
        [ "$(cat "$f")" = "$max" ] || continue
        core_id=$(cat "$d"/topology/core_id 2>/dev/null) || continue
        case "$seen" in *" $core_id "*) continue ;; esac
        seen="$seen$core_id "
        cpu=${d##*/cpu}
        list="${list:+$list,}$cpu"
    done
    [ -n "$list" ] || return 1
    printf '%s\n' "$list"
}

cpu_list=$(pcore_cpu_list) || cpu_list=''
if [ -n "$cpu_list" ] && command -v taskset >/dev/null 2>&1; then
    runner="taskset -c $cpu_list"
    echo "pinning benchmarks to CPUs: $cpu_list"
else
    runner=''
    echo "warning: could not identify performance cores; running unpinned"
fi

# Let the benchmark derive its pool width from the affinity mask set above.
# Idle between the heavy groups so a thermally limited CPU can recover.
BENCH_COOLDOWN_SECS=${BENCH_COOLDOWN_SECS:-15}
export BENCH_COOLDOWN_SECS

$runner cargo bench 2>&1 | tee bench-output.txt

./compare.py bench-output.txt --out-md=tmp323928421

# Describe the machine the numbers above were produced on.
cpu_model=$(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | head -1)
cpu_sockets=$(lscpu | sed -n 's/^Socket(s):[[:space:]]*//p' | head -1)
cpu_per_socket=$(lscpu | sed -n 's/^Core(s) per socket:[[:space:]]*//p' | head -1)
cpu_cores=$((cpu_sockets * cpu_per_socket))
cpu_threads=$(nproc)
cpu_max=$(lscpu | sed -n 's/^CPU max MHz:[[:space:]]*//p' | head -1 \
    | awk '{ printf "%.2f GHz", $1 / 1000 }')
mem_total=$(free -h | awk '/^Mem:/ { print $2 }')
rustc_ver=$(rustc -V)

{
    echo "Benchmark results across ring domains:"
    echo ""
    echo "Hardware:"
    echo ""
    echo "- CPU: $cpu_model ($cpu_cores cores / $cpu_threads threads, boost $cpu_max)"
    echo "- Memory: $mem_total"
    echo "- Toolchain: $rustc_ver"
    echo "- Benchmark threads: $BENCH_THREADS (rayon pool, pinned)"
    echo ""
    echo "Notes on reading the table:"
    echo ""
    echo "- \`canary_before\` / \`canary_after\` are the same fixed benchmark run at the"
    echo "  start and end of each domain block. They measure nothing about the library;"
    echo "  they expose CPU thermal drift. If the two disagree by more than a few percent,"
    echo "  the rest of that column is not trustworthy."
    echo "- \`open_and_create*\` times \`open\` **and** \`create\` together, which is the full"
    echo "  wallet-side cost of producing a proof. Subtract \`open_at_fill_level\` to get the"
    echo "  air-gapped \`create\` half on its own."
    echo "- \`batch_validate/single_ring\` shares one ring across the whole batch, so the"
    echo "  backend builds one ring verifier for all of it. \`multi_ring\` gives each proof"
    echo "  its own ring, forcing a rebuild per item. The gap is how much of the batching"
    echo "  win comes from verifier reuse rather than the batched pairing check."
    echo "- Rows that are flat across fill levels or across domain columns are deliberate"
    echo "  regression guards on operations that are O(1) in the ring; see the module docs"
    echo "  in \`benches/verifiable_validate.rs\`."
    echo ""
    cat tmp323928421
} > README.md

rm tmp323928421
