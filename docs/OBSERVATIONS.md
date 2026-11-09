# Observations and limits

Development observations preceded the final signed candidate. The candidate receipt separately records exact source, actual archive hashes and native executions. Preliminary raw data was retained privately; it is not relabeled as public native CI or a benchmark of a released binary.

A Windows six-run vertical slice with a 100 ms drain exposed generator misses and thousands of slow-case rejections. A later fixed 20 ms drain additionally exposes admitted work still censored at cutoff. The final policy is 20 ms; results from different drain settings are never pooled. The independent oracle reconstructs all partitions, exact ranks and the offered schedule from the raw rows.

A separate Windows BenchmarkDotNet ShortRun (one launch, three warmup/measurement iterations) observed mean batched clock-read cost 9.446 ns and read-plus-preallocated-store 10.103 ns on its recorded host. These are isolated amortized primitive costs. The clock's timestamp granularity/accuracy is a different quantity; those numbers do not establish a 9 ns per-event timestamp resolution or complete instrumentation cost. No cost is subtracted from a reported latency. ShortRun/environment variance limits conclusions; no implementation speed improvement was tested or claimed. The first BDN attempt executed zero benchmarks because its working directory was wrong; it was retained as a failure, and the launcher now rejects missing statistical reports.

dotnet-trace 10.0.750501 captured only an explicitly launched synthetic child with a 32 MiB buffer and a 5-second maximum. The private development trace was about 963 KB; trace-on and trace-off raw datasets were verified separately. Capture is not causal interpretation; no unrelated process, private system or account was inspected.

Public/native CI performance values on shared runners are not pass thresholds. Full source tests, local archive executions, CI artifacts and actual public downloads remain distinct. WSL is a VM, one local process has one monotonic clock, and missing power/virtualization metadata is UNKNOWN. OS scheduling, runtime/JIT, first use, warmup quality, queue choice and the observer affect the result.

Default datasets have at most 5,000 completions each and cannot support this project's p99.9 display floor of 100,000. Suppressing it is intentional. A future larger controlled experiment must retain the same bounds/accounting and disclose its environment; this note does not claim it was run.
