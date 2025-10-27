Current difference between small and big rings:

| Function | Small (median) | Big (median) | big/small | % change | Trend |
|---|---:|---:|---:|---:|---|
| verifiable_push_all_members_in_one_time | 28.688 ms | 1.718 s | 59.90 | 5890.3% | regressed |
| verifiable_open | 49.728 ms | 1.792 s | 36.03 | 3503.2% | regressed |
| verifiable_create | 134.440 ms | 2.769 s | 20.60 | 1960.0% | regressed |
| verifiable_create_for_255_ring_size | 73.683 ms | 1.501 s | 20.37 | 1936.6% | regressed |
| verifiable_open_for_255_ring_size | 40.979 ms | 330.170 ms | 8.06 | 705.7% | regressed |
| verifiable_validate_for_255_ring_size | 12.098 ms | 35.800 ms | 2.96 | 195.9% | regressed |
| verifiable_is_valid_for_255_ring_size | 12.062 ms | 35.501 ms | 2.94 | 194.3% | regressed |
| verifiable_is_valid | 12.002 ms | 33.741 ms | 2.81 | 181.1% | regressed |
| verifiable_validate | 14.939 ms | 34.124 ms | 2.28 | 128.4% | regressed |
| verifiable_push_one_member_in_almost_full | 682.750 µs | 1.011 ms | 1.48 | 48.1% | regressed |
| verifiable_finish_members_full | 87.820 ns | 102.230 ns | 1.16 | 16.4% | regressed |
| verifiable_finish_members | 85.906 ns | 95.205 ns | 1.11 | 10.8% | regressed |
| verifiable_new_secret_for_255_ring_size | 85.470 µs | 87.010 µs | 1.02 | 1.8% | same |
| ed25519_verify | 40.230 µs | 40.514 µs | 1.01 | 0.7% | same |
| verifiable_is_member_valid_for_255_ring_size | 78.683 µs | 78.686 µs | 1.00 | 0.0% | same |
| verifiable_alias_in_contex_for_255_ring_sizet | 124.840 µs | 123.610 µs | 0.99 | -1.0% | same |
| verifiable_finish_members_for_255_ring_size | 90.320 ns | 89.430 ns | 0.99 | -1.0% | same |
| verifiable_start_members | 1.189 µs | 1.176 µs | 0.99 | -1.1% | same |
| verifiable_verify_signature_for_255_ring_size | 588.630 µs | 580.700 µs | 0.99 | -1.3% | same |
| verifiable_member_from_secret_for_255_ring_size | 47.610 ns | 46.881 ns | 0.98 | -1.5% | same |
| verifiable_finish_members_full_for_255_ring_size | 89.482 ns | 87.813 ns | 0.98 | -1.9% | same |
| verifiable_member_from_secret | 48.516 ns | 47.586 ns | 0.98 | -1.9% | same |
| verifiable_sign | 298.840 µs | 287.410 µs | 0.96 | -3.8% | improved |
| verifiable_is_member_valid | 78.798 µs | 75.146 µs | 0.95 | -4.6% | improved |
| verifiable_start_members_for_255_ring_size | 1.231 µs | 1.166 µs | 0.95 | -5.3% | improved |
| verifiable_sign_for_255_ring_size | 316.430 µs | 298.970 µs | 0.94 | -5.5% | improved |
| verifiable_alias_in_context | 123.240 µs | 115.710 µs | 0.94 | -6.1% | improved |
| verifiable_new_secret | 91.728 µs | 85.436 µs | 0.93 | -6.9% | improved |
| verifiable_verify_signature | 579.120 µs | 535.990 µs | 0.93 | -7.4% | improved |
| verifiable_push_members_for_255_ring_size | 33.574 ms | 28.414 ms | 0.85 | -15.4% | improved |
| verifiable_push_one_member_in_almost_full_for_255_ring_size | 1.009 ms | 665.590 µs | 0.66 | -34.0% | improved |
