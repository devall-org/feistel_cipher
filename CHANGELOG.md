# Changelog

## 1.1.0

- Added `backfill_for_v1_column/5` for filling encrypted columns on existing rows.
- Backfill treats both `NULL` and `-1` as pending values.
- Added and clarified backfill documentation for trigger-based workflows.

## 1.0.0

- Renamed `bits` to `data_bits`.
- Added `time_bits`, `time_bucket`, `time_offset`, and `encrypt_time`.
- Introduced v1 PostgreSQL function and trigger APIs with `_v1` suffixes.
- Kept `time_bits: 0` as the backward-compatible path for v0.14.x and v0.15.x users.
