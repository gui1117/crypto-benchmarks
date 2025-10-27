#!/bin/sh

cargo bench > big-bench.txt
cargo bench --features small-ring > small-bench.txt

./compare.py small-bench.txt big-bench.txt --out-md=tmp323928421
(echo "Current difference between small and big rings:"; echo ""; cat tmp323928421) > README.md
rm tmp323928421
