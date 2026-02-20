#!/bin/sh

cargo bench 2>&1 | tee bench-output.txt

./compare.py bench-output.txt --out-md=tmp323928421
(echo "Current difference between domain11 (255 members) and domain16 (16127 members):"; echo ""; cat tmp323928421) > README.md
rm tmp323928421
