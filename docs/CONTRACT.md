# Measurement and accounting contract

One local process and one Stopwatch monotonic clock. Absolute clock values are never subtracted across hosts. CSV stage values are integer ticks relative to one measured origin. Frequency and empirical minimum positive adjacent-read delta are recorded; nominal tick frequency or a minimum observed read delta is not an accuracy guarantee.

The logical offered schedule is independent of the clock frequency: ASCII rows "index,plannedOffsetMicroseconds,workUnits,plannedFailure\\n" are SHA256 hashed. plannedOffsetMicroseconds=index*periodUs. For timing, a period becomes floor(periodUs*frequency/1,000,000) ticks; each intended time is index*that period. Work units are 1+((index*1103515245+seed) modulo 2^32) modulo 4; plannedFailure is ((index+seed) modulo 2^32) modulo 97 == 0. Both modes share these inputs. Wall-clock visits and actual admissions may differ and remain visible.

Stage definitions:
- intended: fixed planned arrival, unaffected by generator blocking or OS scheduling.
- observed: generator visit after waiting for the intended arrival, null if not visited by shutdown.
- actual_send: observed issue stamp when the generator attempts adapter admission. It is null on a generator miss.
- enqueue: stamp immediately before a successful nonblocking Channel.TryWrite; null when rejected. This is a declared admission stamp, not an internal queue timestamp.
- service_start: the consumer's observed start, null if not reached by cutoff.
- completion: observed terminal success/failure by cutoff, null otherwise. A configured work target is not itself an observed completion.

The dedicated generator never waits for channel space: FullMode.Wait is paired with TryWrite, which returns false when full; DropWrite is not used. A request beyond generator-lateness budget or after cutoff is missed before admission. An issue reaching the adapter after cutoff is rejected. A full queue rejects without silently shifting the nominal schedule.

The fixed cutoff is last intended arrival + drain ticks. Consumer work/start/completion is retained only if observed by that cutoff. Joining/cancelling threads afterward does not convert censored work into completed work. Each run has its own separate whole-pipeline warmup; warmup planned/completed counts are reported and excluded from all measured records/ranks. Warmup is not proof of steady state.

The four disjoint identities are in README. Deadline expiry is strictly later than intended+deadline. Completed deadline excess and not-completed deadline expiry are separate orthogonal flags. A planned synthetic failed outcome counts in completed/failure, not as another extra disjoint request.

Ranks are empirical nearest-rank order statistics: ceil(N*p/q)-th ordered observed value. E2E = completion-intended, queue = service_start-enqueue, service = completion-service_start; all ranks use completed records only. No completed samples means null ranks, never zero latency. p99.9 is suppressed below N=100,000; this does not claim statistical confidence above the floor.

Resource bounds: at most 200,000 planned samples, raw capacity at most 200,000, channel capacity 1..4,096, 64 MiB CSV byte cap, nominal measured schedule+drain at most 30 seconds. Warmup is separate and bounded by the smaller of requested warmup count (at most 10,000) and measured count, with drain at most 100 ms. A requested count above raw capacity stops before allocating/launching the profile and returns INCOMPLETE with no statistical result. Worker/join errors also produce INCOMPLETE without a complete-statistics claim. Output failures never publish a COMPLETE summary.

The raw cap is deliberately checked before the known fixed-size schedule starts; this avoids pretending that a partially recorded schedule is complete. The process never silently discards a sample and then reports a complete-result percentile. Valid COMPLETE accounting can contain only misses/rejections/censored work.

This is neither coordinated-omission correction for an arbitrary application nor causal attribution from a histogram. It is a bounded open-loop synthetic evidence experiment with an explicit intended schedule and independent raw oracle.
