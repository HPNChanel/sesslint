# T-02: Full-scale benchmark

- Status: done
- Phase: 0 (order 2, parallel with T-01/T-04)
- Targets: `bench/PERF_NOTES.md` (disclosure verified)

## Execution & Measured Numbers

Ran:
```bash
python bench/perf_250k.py --records 250000 --time-budget 15.0 --mem-budget 512.0
```

Results:
- Records: 250,000 (~99.45 MB synthetic session JSONL)
- Streaming parse: 250,000 items in 4.109s (60,849 items/sec)
- Integrity check: 11.321s (verdict: 0 findings, assurance=A3)
- Total wall time: 15.430s (budget: 15.0s, breach margin 0.430s — reduced from 19.949s pre-optimization)
- Peak RSS memory: 785.52 MB (budget: 512.0 MB)
- Tracemalloc heap peak: 0.410 MB (streaming heap bounded)
- Disclosure verified in `bench/PERF_NOTES.md` per mandatory disclosure rule.

## Acceptance

Benchmark executed; measured numbers recorded; disclosure verified.
