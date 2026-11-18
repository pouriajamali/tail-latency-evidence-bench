# Tail-Latency Evidence Bench

A small C#/.NET experiment that keeps the missing work visible. The generator follows a fixed open-loop schedule. A deliberately slow consumer fills a bounded channel; rejections and unfinished admissions remain in the result beside completed-only latency ranks.

Offline synthetic work only. No NIC, wire, exchange, cross-host latency, production HFT capacity or speed-improvement claim.

## Architecture review

Read the [architecture case study](docs/ARCHITECTURE-CASE-STUDY.md) for the decision, rejected alternatives, failure examples, frozen-release evidence and short English/Persian introductions. Follow the [30-minute four-project review](https://github.com/pouriajamali/trading-execution-lab/blob/main/docs/FLAGSHIP-REVIEW.md) for a guided discussion. The [evidence index](docs/FLAGSHIP-EVIDENCE.json) separates runtime/tag CI from later documentation commits.

## Start with the decisions and their proofs

| Decision | Evidence |
| --- | --- |
| Do not hide overload by blocking the generator | Same nominal schedule/seed for healthy and slow cases; actual admissions/rejections recorded |
| Do not treat missing work as fast work | Generator misses, rejections and cutoff-censored admissions are separate counts |
| Do not invent a tail from a small sample | Exact raw-sample ranks; p99.9 suppressed below 100,000 completions |
| Do not silently lose measurement records | A requested run beyond the record cap returns INCOMPLETE before starting, without quantiles |
| Do not trust the producer's own statistics | Independent Python integer/Fraction oracle and eight corrupted-data counterexamples |

## Run the preview

Published preview: [`v0.1.0-preview.1`](https://github.com/pouriajamali/tail-latency-evidence-bench/releases/tag/v0.1.0-preview.1). Download **[Windows x64](https://github.com/pouriajamali/tail-latency-evidence-bench/releases/download/v0.1.0-preview.1/tail-latency-evidence-bench-v0.1.0-preview.1-win-x64.zip)**, **[Linux x64](https://github.com/pouriajamali/tail-latency-evidence-bench/releases/download/v0.1.0-preview.1/tail-latency-evidence-bench-v0.1.0-preview.1-linux-x64.tar.gz)** or [source](https://github.com/pouriajamali/tail-latency-evidence-bench/releases/download/v0.1.0-preview.1/tail-latency-evidence-bench-v0.1.0-preview.1-source.zip). Get the [checksums](https://github.com/pouriajamali/tail-latency-evidence-bench/releases/download/v0.1.0-preview.1/SHA256SUMS.txt), [checksum signature](https://github.com/pouriajamali/tail-latency-evidence-bench/releases/download/v0.1.0-preview.1/SHA256SUMS.txt.sig) and [public key](https://github.com/pouriajamali/tail-latency-evidence-bench/releases/download/v0.1.0-preview.1/SIGNING-PUBLIC-KEY.pub); verify downloaded bytes with [PROVENANCE.md](PROVENANCE.md) before executing them. Local builds and CI artifacts are separate from published releases.

From the extracted Windows x64 package:

```powershell
.\tail-evidence.exe --help
python tools/native_demo.py --cli tail-evidence.exe --out artifacts/demo
if ($LASTEXITCODE -ne 0) { throw 'Evidence validation failed' }
Get-Content artifacts/demo/receipt.json
Get-Content artifacts/demo/oracle.json
```

From the extracted native Linux x64 package:

```sh
./tail-evidence --help &&
python3 tools/native_demo.py --cli ./tail-evidence --out artifacts/demo &&
cat artifacts/demo/receipt.json
```

The self-contained CLI needs no SDK or online service. Python 3.12+ runs the independent verifier; OpenSSH verifies package provenance. Windows and Linux run their native CLI. Existing WSL can run the Linux package; its measurements are VM observations, never bare-metal or cross-platform speed evidence.

The demo runs three healthy/slow pairs, 5,000 planned requests each, a 100 microsecond period, channel capacity 64 and a fixed 20 millisecond drain. All cases use the same offered schedule, seed, cutoff/deadline settings and executable. The service loop's configured busy-wait target changes from 10 to 500 microseconds per work unit; this is a controlled overload fixture, not an optimized application. Sample values vary with OS load, scheduling, virtualization, clock and JIT. CI checks arithmetic/chronology/caps, without performance pass thresholds.

Use a new output directory for every attempt. Raw CSV, summary JSON and independent receipts are retained. COMPLETE means complete accounting; it does not mean every request was attempted, admitted or successful.

## Read the result before the percentile

```text
planned  = generatorMissed + attempted
attempted = admitted + rejected
admitted = completedAtCutoff + censoredAtCutoff
completedAtCutoff = success + failure
```

Generator lateness and deadline flags are orthogonal to those partitions. A completed synthetic failure still has a completion timestamp. Censored work has no observed completion by the fixed cutoff. An unvisited planned arrival at cutoff is a generator miss; no actual-send timestamp is invented.

Ranks use completed records only and keep their denominator beside them. Missing work can bias those ranks. p99.9's 100,000-completion display floor is a policy, not a confidence guarantee. See [measurement contract](docs/CONTRACT.md) and [observations and limitations](docs/OBSERVATIONS.md).

## Build and separate diagnostics

Source requires exact .NET SDK 10.0.403, runtime 10.0.14 and C#14:

```sh
dotnet restore TailLatencyEvidence.slnx --locked-mode
dotnet build TailLatencyEvidence.slnx -c Release --no-restore -m:1
dotnet run --project tests/Evidence.Tests -c Release --no-build -- -result-xml artifacts/unit.xml
```

The runtime CLI uses BCL only. BenchmarkDotNet 0.15.8, xUnit v3 4.0.3 and dotnet-trace 10.0.750501 are pinned development/test tools, excluded from the shipped runtime graph. To repeat the isolated observer benchmark, run from `benchmarks/ObserverBench` and supply a NEW artifacts directory:

```sh
dotnet run -c Release -- ../../artifacts/observer
```

Its job explicitly uses `DontEnforcePowerPlan`. A successful process with zero executed benchmarks is rejected. This measures clock/read-and-store primitives separately; it is not the whole harness's observer cost and is not subtracted from end-to-end timings.

```mermaid
flowchart LR
  G[Fixed nominal schedule] --> A[Nonblocking admission]
  A --> Q[Bounded Channel]
  A --> R[Raw records including misses and rejects]
  Q --> C[Single consumer]
  C --> R
  R --> O[Independent offline oracle]
  O --> S[Counts and completed-only ranks]
```

Optional developer tracing also requires the SDK: restore the local tool manifest, then collect only an explicitly launched lab child. Keep trace-on data separate from trace-off data:

```sh
dotnet tool restore
dotnet tool run dotnet-trace collect --buffersize 32 --profile dotnet-sampled-thread-time,dotnet-common --duration 00:00:05 --output artifacts/owned.nettrace -- ./tail-evidence run healthy artifacts/traced
```

Use the appropriate CLI path from the source/package working directory; do not attach the tool to unrelated processes. Traces stay private by default. A captured trace does not prove causality or a latency improvement.

See [decisions](docs/ADR.md), [runbook/review](docs/RUNBOOK.md), [notices](NOTICE.md) and [provenance](PROVENANCE.md). Original code: MIT; no private/shared project code, account/market connection or career-material change.

[CI resource policy](docs/CI-POLICY.md): documentation-only changes get real lightweight document/pipeline checks; source, tag and ordinary manual runs retain native validation. A separate, single-use M1 consumer profile is documented in that policy; admission and M1 completion require its actual receipts. Published runtime tags and release assets remain unchanged.

## Source readability

The current source expands compact C# layout for review. The published preview links identify its frozen runtime release. Formatting preserves complete syntax, token text and values, comments and directives; it does not introduce a runtime behavior or performance claim.

To reproduce a published package, use its exact original runtime source: [v0.1.0-preview.1 source](https://github.com/pouriajamali/tail-latency-evidence-bench/tree/6158f7f8a9a8e4fd7c12ed575f427d7117b89801) (`6158f7f8a9a8e4fd7c12ed575f427d7117b89801`). Later `main` layout is reviewed separately from those frozen release commits.

## Bounded M1 status

M1 remains HOLD; zero native M1 cases, archive downloads or SDK calls have run. Existing preview binaries/signatures, complete ESET proof and healthy controls are retained. The source keeps the platform/WMI removal, exact local canonical binding, finite provider queue correction and separate source-bound owned-SSH role; SSH dependencies are not imposed on Python module handles.

Libcrypto exact-file/native-catalog/current-offline-chain proof passed. The earlier owned SSH operation verified the public signature but did not establish trusted closure: six additional providers and a .rdata mismatch were recorded together. The approved consolidated continuation read only those six files. Native signatures succeeded for all six; current NoFlag offline chains passed for winrnr.dll, nlansp_c.dll, wshbth.dll and kernel.appcore.dll. The chains for napinsp.dll and DSPARSE.dll failed with NotTimeValid on the shared signer (expired 2024-11-14) and PCA2011 issuer (expired 2026-10-19).

The owner-authorized fresh 300-second timestamp supplement ran once on 2026-11-18, using only the two failed exact identities. Native signature/countersigner verification succeeded. Authenticated references were 2024-07-03T04:30:29.386Z for napinsp.dll and 2024-09-05T18:55:50.774Z for DSPARSE.dll; independent signer and timestamp chains passed at those times with NoFlag, Offline revocation, downloads disabled and existing roots. The original current-time False/NotTimeValid results remain unchanged.

Independent current-chain native revocation metadata exists with result zero and freshness 817 seconds for all five distinct nonroot certificates. The wrapper captured no CRL context or signed CRL/OCSP validity interval. Its conservative CRL-context path therefore stopped with PRESENT_TIME_NONREVOCATION_NOT_PROVEN; it has not validated an OCSP alternative. This is an evidence-capture limitation, not evidence that the cache lacks valid data, that a certificate is revoked, or that its signature is bad. Timestamp/historical validity alone does not complete the agreed current-revocation proof.

The gate prevented the changed SSH admission again: zero new SSH invocations, module observations, image reads or native M1 cases. The helper exited naturally in its inherited capped Job and the canonical lease was released after all owned terminal evidence. The one execution is consumed; neither the earlier window nor the new window is reset or extended. No runtime retry, cache/store/clock/trust/security change or healthy proof replay follows this hold.

The subsequent five-certificate artifact proof was authorized for one fresh 300-second window, at most five artifacts / 5MiB. Canonical-lane ownership remained BUSY. An initial bounded wait and one continuation used the identical original start/deadline; neither started a target child or claimed the lease. No new artifact/cache/certificate validation, SSH or image observation occurred. The prepared cache-only helper is source preparation only. Another participant's lease was preserved; M1 remains blocked on lane availability and the unchanged revocation proof, with no automatic fresh window.

The [owned-SSH role profile](tools/m1/metadata/owned-ssh-profile.json) stays HOLD. The consolidated tool's file-proof prefix ran; its SSH/mapping/CFG branch is source preparation only and is not runtime-validated or admitted. All unresolved mapping claims remain pending, including libcrypto .rdata. Existing three role-guard checks and healthy ESET/control evidence are reused.

GitHub Actions is prohibited. CI was not run per owner instruction. Signed task-branch pushes use [skip ci] after checking actual triggers; no tag, PR, merge, release, protection or truststore change is made. Source/evidence delivery is separate from complete M1 delivery; original Windows/Linux fixed cases are pending.
