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

here=$(dirname "$0")
work=$(mktemp -d) || exit 1
trap 'rm -rf "$work"' EXIT INT TERM

# `cargo bench | tee` would report tee's exit status, so stash cargo's own status and
# check it: a crashed or interrupted run must not silently regenerate README.md from a
# truncated bench-output.txt.
{ $runner cargo bench 2>&1; echo $? >"$work/status"; } | tee bench-output.txt
bench_status=$(cat "$work/status" 2>/dev/null || echo 1)
if [ "$bench_status" -ne 0 ]; then
    echo "error: cargo bench failed (exit $bench_status); README.md left unchanged" >&2
    exit "$bench_status"
fi

# --strict makes dropped benchmarks, unparsable timings and partial domain coverage
# fatal, for the same reason: a partial table must not be published as a complete one.
if ! "$here/compare.py" bench-output.txt --strict --out-md="$work/table.md"; then
    echo "error: compare.py rejected bench-output.txt; README.md left unchanged" >&2
    exit 1
fi

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

if [ -n "$cpu_list" ]; then
    pinned_cpus=$cpu_list
    pinned_count=$(printf '%s' "$cpu_list" | awk -F, '{ print NF }')
else
    pinned_cpus="unpinned"
    pinned_count=$cpu_threads
fi

# Record which revision of the measured crate produced these numbers. Cargo.lock is the
# only thing that pins it (Cargo.toml tracks the default branch), and without this the
# table cannot be tied back to any particular upstream state.
lock_block=$(grep -A3 '^name = "verifiable"$' Cargo.lock)
verifiable_ver=$(printf '%s\n' "$lock_block" | sed -n 's/^version = "\(.*\)"/\1/p' | head -1)
verifiable_src=$(printf '%s\n' "$lock_block" | sed -n 's/^source = "\(.*\)"/\1/p' | head -1)
verifiable_rev=${verifiable_src##*#}
verifiable_repo=${verifiable_src%#*}
verifiable_repo=${verifiable_repo#git+}

{
    echo "Benchmark results across ring domains:"
    echo ""
    echo "Measured crate:"
    echo ""
    echo "- verifiable $verifiable_ver"
    echo "- $verifiable_repo"
    echo "- revision \`$verifiable_rev\`"
    echo ""
    echo "Hardware:"
    echo ""
    echo "- CPU: $cpu_model ($cpu_cores cores / $cpu_threads threads, boost $cpu_max)"
    echo "- Memory: $mem_total"
    echo "- Toolchain: $rustc_ver"
    echo "- Benchmark CPUs: $pinned_cpus ($pinned_count rayon threads)"
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
    echo "- \`batch_validate/single_ring/1024\` has no domain16 figure on purpose. Every proof"
    echo "  in the batch needs its own \`open\`, which is seconds at that ring size, so the"
    echo "  fixture alone would be roughly 45 minutes of untimed setup. That blank cell is a"
    echo "  measurement not taken, not one that failed; \`compare.py\` knows about this single"
    echo "  exclusion and still rejects every other gap."
    echo "- Rows that are flat across fill levels or across domain columns are deliberate"
    echo "  regression guards on operations that are O(1) in the ring; see the module docs"
    echo "  in \`benches/verifiable_validate.rs\`."
    echo ""
    cat "$work/table.md"
} > README.md
