Benchmark results across ring domains:

Hardware:

- CPU: 11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz (4 cores / 8 threads, boost 4.70 GHz)
- Memory: 14Gi
- Toolchain: rustc 1.92.0 (ded5c06cf 2025-12-08)

| Function | Domain11 (255) | Domain12 (767) | Domain16 (16127) |
|---|---:|---:|---:|
| alias_in_context | 285.240 µs | 287.110 µs | 282.650 µs |
| batch_validate/1 | 5.153 ms | 5.172 ms | 5.700 ms |
| batch_validate/2 | 7.123 ms | 7.104 ms | 7.726 ms |
| batch_validate/4 | 10.994 ms | 10.977 ms | 11.607 ms |
| batch_validate/8 | 18.597 ms | 18.584 ms | 19.219 ms |
| batch_validate/16 | 32.963 ms | 33.156 ms | 33.637 ms |
| batch_validate/32 | 62.771 ms | 61.269 ms | 61.929 ms |
| batch_validate/64 | 116.670 ms | 116.320 ms | 116.980 ms |
| batch_validate/128 | 226.430 ms | 226.270 ms | 227.360 ms |
| create | 121.160 ms | 234.960 ms | 3.561 s |
| create_at_fill_level/full | 120.570 ms | 234.620 ms | 3.564 s |
| create_at_fill_level/half | 105.860 ms | 195.500 ms | 2.599 s |
| create_at_fill_level/nearly_empty | 94.170 ms | 157.630 ms | 1.656 s |
| create_at_fill_level/quarter | 100.350 ms | 175.000 ms | 2.102 s |
| create_at_fill_level/three_quarters | 113.110 ms | 215.340 ms | 3.075 s |
| ed25519_verify |  |  |  |
| finish_members | 89.285 ns | 84.960 ns | 85.722 ns |
| finish_members_at_fill_level/full | 87.461 ns | 86.131 ns | 85.738 ns |
| finish_members_at_fill_level/half | 87.883 ns | 86.321 ns | 86.282 ns |
| finish_members_at_fill_level/nearly_empty | 87.672 ns | 86.935 ns | 85.964 ns |
| finish_members_at_fill_level/quarter | 88.446 ns | 85.801 ns | 86.207 ns |
| finish_members_at_fill_level/three_quarters | 87.094 ns | 86.038 ns | 86.057 ns |
| finish_members_full | 88.562 ns | 86.120 ns | 86.188 ns |
| is_member_valid | 100.930 µs | 100.990 µs | 98.892 µs |
| is_valid | 6.078 ms | 6.085 ms | 6.683 ms |
| is_valid_at_fill_level/full | 6.045 ms | 6.018 ms | 6.726 ms |
| is_valid_at_fill_level/half | 6.039 ms | 6.059 ms | 6.743 ms |
| is_valid_at_fill_level/nearly_empty | 6.038 ms | 6.045 ms | 6.729 ms |
| is_valid_at_fill_level/quarter | 6.031 ms | 6.056 ms | 6.763 ms |
| is_valid_at_fill_level/three_quarters | 6.041 ms | 6.046 ms | 6.729 ms |
| member_from_secret | 62.370 ns | 62.327 ns | 61.738 ns |
| new_secret | 107.730 µs | 108.060 µs | 107.360 µs |
| open | 48.732 ms | 123.850 ms | 2.274 s |
| open_at_fill_level/full | 48.647 ms | 123.410 ms | 2.275 s |
| open_at_fill_level/half | 34.246 ms | 75.329 ms | 1.302 s |
| open_at_fill_level/nearly_empty | 21.258 ms | 35.155 ms | 369.380 ms |
| open_at_fill_level/quarter | 28.019 ms | 53.807 ms | 814.700 ms |
| open_at_fill_level/three_quarters | 41.174 ms | 99.473 ms | 1.787 s |
| push_all_members_in_one_time | 39.485 ms | 110.130 ms | 2.137 s |
| push_one_member_at_fill_level/empty | 758.280 µs | 756.500 µs | 756.780 µs |
| push_one_member_at_fill_level/full_minus_one | 754.530 µs | 746.330 µs | 746.690 µs |
| push_one_member_at_fill_level/half | 739.200 µs | 742.960 µs | 737.870 µs |
| push_one_member_at_fill_level/quarter | 744.740 µs | 754.750 µs | 738.320 µs |
| push_one_member_at_fill_level/three_quarters | 756.380 µs | 739.380 µs | 736.690 µs |
| push_one_member_in_almost_full | 790.810 µs | 746.510 µs | 747.080 µs |
| sign | 212.280 µs | 210.570 µs | 209.910 µs |
| start_members | 82.481 ns | 78.102 ns | 81.539 ns |
| validate | 6.079 ms | 6.091 ms | 6.690 ms |
| validate_at_fill_level/full | 6.048 ms | 6.122 ms | 6.729 ms |
| validate_at_fill_level/half | 6.057 ms | 6.051 ms | 6.755 ms |
| validate_at_fill_level/nearly_empty | 6.026 ms | 6.022 ms | 6.720 ms |
| validate_at_fill_level/quarter | 6.036 ms | 6.055 ms | 6.763 ms |
| validate_at_fill_level/three_quarters | 6.062 ms | 6.037 ms | 6.736 ms |
| verify_signature | 421.260 µs | 422.830 µs | 415.040 µs |
