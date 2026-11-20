# .NET 10 servicing evidence - 2026-11-20

See [receipt](receipt.json). The original M1/runtime is immutable. This new preview changes SDK/runtime servicing only; Windows is observed experimental with formal vendor support NOT_CONFIRMED. Native Linux and Windows build/test/package checks are separate. The Linux runtime package signature data was independently verified on Windows; native Linux NuGet verification timeout is retained, never relabeled PASS. No Actions, benchmark/trace/M1 replay or production/security/speed claim.

Native Windows and Linux each passed 15 unit tests, three actual source/owner/SDK-byte rejection controls, locked restores, build and native package checks. All six new release assets were published and independently public-download/hash verified. The signed tag identifies the Linux/release source; exact Windows archive source is recorded separately with identical product/build/package inputs. Linux publish completed natively; its retained output was assembled as data on Windows without another SDK call, then checked natively on Linux. This later documentation commit records final delivery. No Actions or healthy M1/benchmark/trace replay occurred.

[Published preview](https://github.com/pouriajamali/tail-latency-evidence-bench/releases/tag/v0.1.0-preview.2). Use the known-key checksum signature and SHA256SUMS before execution.
