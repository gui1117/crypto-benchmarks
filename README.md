Benchmark results across ring domains:

Measured crate:

- verifiable 0.5.0
- https://github.com/paritytech/verifiable.git
- revision `1f9f67524acce0d9c46dbbb566f84ce52757b114`

Hardware:

- CPU: 11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz (4 cores / 8 threads, boost 4.70 GHz)
- Memory: 14Gi
- Toolchain: rustc 1.92.0 (ded5c06cf 2025-12-08)
- Benchmark CPUs: 0,1,2,3 (4 rayon threads)

Notes on reading the table:

- `canary_before` / `canary_after` are the same fixed benchmark run at the
  start and end of each domain block. They measure nothing about the library;
  they expose CPU thermal drift. If the two disagree by more than a few percent,
  the rest of that column is not trustworthy.
- `open_and_create*` times `open` **and** `create` together, which is the full
  wallet-side cost of producing a proof. Subtract `open_at_fill_level` to get the
  air-gapped `create` half on its own.
- `batch_validate/single_ring` shares one ring across the whole batch, so the
  backend builds one ring verifier for all of it. `multi_ring` gives each proof
  its own ring, forcing a rebuild per item. The gap is how much of the batching
  win comes from verifier reuse rather than the batched pairing check.
- `batch_validate/single_ring/1024` has no domain16 figure on purpose. Every proof
  in the batch needs its own `open`, which is seconds at that ring size, so the
  fixture alone would be roughly 45 minutes of untimed setup. That blank cell is a
  measurement not taken, not one that failed; `compare.py` knows about this single
  exclusion and still rejects every other gap.
- Rows that are flat across fill levels or across domain columns are deliberate
  regression guards on operations that are O(1) in the ring; see the module docs
  in `benches/verifiable_validate.rs`.

| Function | Domain11 (255) | Domain12 (767) | Domain16 (16127) |
|---|---:|---:|---:|
| alias_in_context | 284.030 µs | 275.660 µs | 270.040 µs |
| batch_validate/multi_ring/1 | 4.368 ms | 4.365 ms | 4.808 ms |
| batch_validate/multi_ring/2 | 6.298 ms | 6.320 ms | 7.178 ms |
| batch_validate/multi_ring/4 | 10.142 ms | 10.166 ms | 11.856 ms |
| batch_validate/multi_ring/8 | 17.737 ms | 17.862 ms | 21.144 ms |
| batch_validate/multi_ring/16 | 32.239 ms | 32.565 ms | 39.080 ms |
| batch_validate/multi_ring/32 | 61.296 ms | 61.711 ms | 74.645 ms |
| batch_validate/multi_ring/64 | 119.010 ms | 119.450 ms | 144.700 ms |
| batch_validate/multi_ring/128 | 232.970 ms | 234.740 ms | 288.210 ms |
| batch_validate/single_ring/1 | 4.334 ms | 4.367 ms | 4.774 ms |
| batch_validate/single_ring/2 | 6.025 ms | 6.039 ms | 6.537 ms |
| batch_validate/single_ring/4 | 9.251 ms | 9.249 ms | 9.794 ms |
| batch_validate/single_ring/8 | 15.692 ms | 15.697 ms | 16.200 ms |
| batch_validate/single_ring/16 | 27.879 ms | 27.905 ms | 28.402 ms |
| batch_validate/single_ring/32 | 52.009 ms | 52.008 ms | 52.690 ms |
| batch_validate/single_ring/64 | 99.822 ms | 99.804 ms | 100.400 ms |
| batch_validate/single_ring/128 | 194.980 ms | 195.010 ms | 195.740 ms |
| batch_validate/single_ring/1024 | 1.501 s | 1.501 s |  |
| canary_after | 5.047 ms | 5.061 ms | 5.139 ms |
| canary_before | 5.198 ms | 5.139 ms | 5.175 ms |
| ed25519_verify |  |  |  |
| finish_members_at_fill_level/nearly_empty | 60.679 ns | 59.615 ns | 60.061 ns |
| finish_members_at_fill_level/quarter | 60.640 ns | 60.192 ns | 56.987 ns |
| finish_members_at_fill_level/half | 61.448 ns | 56.033 ns | 59.753 ns |
| finish_members_at_fill_level/three_quarters | 61.211 ns | 59.504 ns | 59.965 ns |
| finish_members_at_fill_level/full | 61.488 ns | 59.838 ns | 60.604 ns |
| is_member_valid | 103.510 µs | 100.760 µs | 96.942 µs |
| is_valid_at_fill_level/nearly_empty | 5.054 ms | 5.088 ms | 5.537 ms |
| is_valid_at_fill_level/quarter | 5.101 ms | 5.059 ms | 5.512 ms |
| is_valid_at_fill_level/half | 5.054 ms | 5.117 ms | 5.557 ms |
| is_valid_at_fill_level/three_quarters | 5.094 ms | 5.084 ms | 5.581 ms |
| is_valid_at_fill_level/full | 5.086 ms | 5.057 ms | 5.526 ms |
| member_from_secret | 55.768 ns | 54.882 ns | 54.707 ns |
| new_secret | 106.120 µs | 101.920 µs | 101.690 µs |
| open_and_create_at_fill_level/nearly_empty | 62.860 ms | 105.890 ms | 1.149 s |
| open_and_create_at_fill_level/quarter | 70.164 ms | 127.710 ms | 1.598 s |
| open_and_create_at_fill_level/half | 77.803 ms | 150.440 ms | 2.068 s |
| open_and_create_at_fill_level/three_quarters | 85.539 ms | 173.670 ms | 2.531 s |
| open_and_create_at_fill_level/full | 93.370 ms | 195.920 ms | 3.009 s |
| open_at_fill_level/nearly_empty | 14.244 ms | 23.832 ms | 258.200 ms |
| open_at_fill_level/quarter | 21.295 ms | 44.916 ms | 706.780 ms |
| open_at_fill_level/half | 28.710 ms | 67.135 ms | 1.174 s |
| open_at_fill_level/three_quarters | 36.203 ms | 89.808 ms | 1.636 s |
| open_at_fill_level/full | 43.517 ms | 111.860 ms | 2.078 s |
| push_all_members_in_one_time | 35.790 ms | 99.181 ms | 1.991 s |
| push_one_member_at_fill_level/empty | 600.280 µs | 600.400 µs | 597.940 µs |
| push_one_member_at_fill_level/quarter | 586.630 µs | 604.220 µs | 582.170 µs |
| push_one_member_at_fill_level/half | 583.730 µs | 585.680 µs | 580.250 µs |
| push_one_member_at_fill_level/three_quarters | 603.240 µs | 586.450 µs | 580.400 µs |
| push_one_member_at_fill_level/full_minus_one | 593.050 µs | 587.210 µs | 588.070 µs |
| sign | 209.250 µs | 200.110 µs | 195.940 µs |
| start_members | 72.010 ns | 66.395 ns | 66.562 ns |
| validate_at_fill_level/nearly_empty | 5.066 ms | 5.081 ms | 5.549 ms |
| validate_at_fill_level/quarter | 5.121 ms | 5.067 ms | 5.526 ms |
| validate_at_fill_level/half | 5.065 ms | 5.113 ms | 5.563 ms |
| validate_at_fill_level/three_quarters | 5.097 ms | 5.082 ms | 5.586 ms |
| validate_at_fill_level/full | 5.075 ms | 5.046 ms | 5.548 ms |
| verify_signature | 372.310 µs | 377.270 µs | 369.610 µs |
