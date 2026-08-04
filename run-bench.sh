#!/bin/sh

cargo bench 2>&1 | tee bench-output.txt

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
    echo ""
    cat tmp323928421
} > README.md

rm tmp323928421
