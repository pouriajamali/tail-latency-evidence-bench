# Decisions

1. Stopwatch, a bounded BCL Channel and two dedicated local threads. No cross-host clocks, extra broker, unsafe queue, mandatory histogram port or new infrastructure project. A declared nonblocking admission avoids moving the intended schedule under overload.
2. Preallocated bounded records and offline export/analysis. The independent Python oracle uses integers and Fraction rather than calling the C# summary producer. Corrupted counts, chronology, ranks, record sets, flags and offered schedules must fail.
3. Explicit complete-accounting versus request success. Misses/rejections/censoring are retained before anyone reads the completed-only rank. A slower/incomplete/unresolved result is useful evidence and is never converted to a speed claim.
4. .NET10 LTS/C#14, pinned supported SDK/runtime, stable xUnit v3, BenchmarkDotNet and dotnet-trace. No preview, Native AOT assumption or package added for a familiar technology name. The shipped CLI uses BCL only; development tools are separate.
5. Independent observer microbenchmark and separate trace-on profile. Host power/timer/security settings are not modified; the BDN job explicitly opts out of power-plan enforcement. Primitive observer numbers are not subtracted from end-to-end data. Tracing an owned child is separate from tracing unrelated systems.
6. Per-platform native execution with shared logical offered-input identity. Windows and WSL/Linux observations have different clocks/environments and are not a valid hardware speed contest.

This demonstrates architecture, failure semantics and review handoff quality. It does not manufacture production HFT, exchange certification, people-management experience or exclusive ownership.
