# Oracle and verifier scope - source review, 2026-11-20

The README's **frozen oracle's known false positives** names a deliberately retained limitation, not a claim that a later verifier fixed it. The standalone oracle shipped in **v0.1.0-preview.2 still has that limitation**. M1's independent preflight witness rejects those inputs. These are different paths and different claims.

This is a source/fixture/receipt review only. No validator, counterexample, native case, healthy test/build/SDK/benchmark, signature, archive download or artifact hash was rerun. No code, runtime tag, binary, package or signature changes follow. This document does not claim new end-to-end runtime acceptance or a hardening fix.

## Exact sources and retained evidence

- Original runtime: signed v0.1.0-preview.1, source `6158f7f8a9a8e4fd7c12ed575f427d7117b89801`. Current signed servicing source/tag: [v0.1.0-preview.2](https://github.com/pouriajamali/tail-latency-evidence-bench/tree/v0.1.0-preview.2), commit `18e1d4a33e694f20fbcb20781e69fbefb663d426`.
- [`tools/oracle.py`](../tools/oracle.py), function `validate`, has the same source in both runtime tags and in the reviewed checkout. Its `expect_incomplete` branch returns before configuration/clock/warmup validation. It checks the schema/header and only INCOMPLETE/reason/header-only records/null statistics there. The returned status is `PASS_INCOMPLETE_CAP_NO_STATISTICAL_RESULT`; this is not a COMPLETE measurement, valid cause/invocation proof or a latency result.
- [`tools/m1/experiment.py`](../tools/m1/experiment.py), `mutate` and `validators`, and the [frozen case plan](../tools/m1/case-plan.json) define N01-N12. These M1 files and [`preflight_witness.py`](../tools/m1/preflight_witness.py) are unchanged from the delivered M1 source `d98e9f606154b88889d9d0f9864388a9e075b3c2` through the current tag/checkout. Source equality was inspected with Git comparisons, not artifact rehashing.
- The existing [M1 receipt](evidence/m1-20261119/receipt.json), `validatorFindings`, records N01-N08 accepted by the original oracle and **12/12 rejected by the independent witness for each RID/mode**, Windows/Linux and normal/optimized. These are historical observations reused against unchanged source, not fresh test results.
- The unchanged [M1 evidence ZIP](https://github.com/pouriajamali/tail-latency-evidence-bench/releases/download/v0.1.0-preview.1/tail-latency-evidence-bench-M1-evidence-20261119.zip) contains exact fixture paths `counterexamples/{win-x64,linux-x64}/N01..N12/{summary.json,raw.csv}`, findings `findings/{RID}/{normal,optimized}.json`, `M1.json`, and frozen `code/`. The ZIP was not fetched, extracted or rehashed for this review; existing retained files/receipts were read.

## What the eight false-positive IDs mean

The base is the raw-cap preflight case: independently fixed count100/rawCapacity99, INCOMPLETE before start, exact header-only raw, null statistics, cutoff0, empty offered-schedule digest, zero warmup. Each mutation changes one of those cause/envelope facts.

| ID | Exact mutation | Existing recorded original oracle | Existing recorded independent witness |
| --- | --- | --- | --- |
| N01 | rawCapacity100, equal to count100 | accepts narrow incomplete branch | rejects configuration mismatch; cap is not exceeded |
| N02 | rawCapacity101, greater than count | accepts | rejects configuration mismatch; cap is not exceeded |
| N03 | count0 | accepts | rejects configuration range |
| N04 | rawCapacity0 | accepts | rejects configuration range |
| N05 | count200001 | accepts | rejects configuration range |
| N06 | cutoffTicks="1" | accepts | rejects nonzero preflight cutoff |
| N07 | offeredScheduleSha256=64 zeroes | accepts | rejects nonempty unstarted schedule digest |
| N08 | warmupPlanned1 | accepts | rejects started warmup |

For example, the retained Windows N01 fixture declares count100/rawCapacity100 yet reports RAW_RECORD_CAP_BEFORE_START with empty raw and null statistics. `findings/win-x64/normal.json` records `originalOracleAccepted=true`, `independentWitnessAccepted=false`. This exact recorded example and unchanged source establish the limitation without replaying it. N09-N12 are separate negative controls; the original oracle rejects them. Do not describe all24 distinct RID fixtures as oracle false positives.

## Current caller paths

| Entry/caller | What it uses | Boundary |
| --- | --- | --- |
| Direct `oracle.py --run ... --expect-incomplete` | frozen incomplete branch | Known N01-N08 limitation remains. It is not a strict preflight-cause validator. |
| `native_demo.py` raw-cap step | requires actual native raw-cap-demo exit4, then calls frozen oracle | Does not add independent configuration/cause checks or invoke the M1 witness. It creates fresh native output; this review does not execute or demonstrate a new end-to-end native-caller bypass. |
| `check_package.py` raw-cap step | actual native CLI exit4, then the same frozen oracle | Checks no statistical/quantile result for that fresh package case; do not promote this subcheck to rejection of every malformed preflight summary. Other package byte/graph/license checks have their own scope. |
| M1 `experiment.validators` / cap99 path | frozen oracle **and** independent witness with external fixed config/recorded invocation | `preflight_witness.validate` checks exact config/ranges, real cap exceedance, invocation/exit, preflight fields, duplicate keys and exact header-only raw. `require(not independentWitness.accepted)` is mandatory for each negative. Oracle acceptance alone cannot satisfy the M1 negative gate. |
| `verify_downloads.py` | pinned checksum signature and selected present archive digests | Archive provenance, not raw-run accounting or preflight-cause validation. It does not evaluate N01-N08. No signature/archive validation was replayed here. |

The witness's PASS is explicitly preflight-envelope/invocation evidence, not proof of zero internal allocations/threads or COMPLETE latency accounting. Complete-case accounting in M1 still uses the frozen raw oracle plus independently fixed configuration; this review does not generalize the preflight witness to arbitrary COMPLETE datasets.

## Result and current entry point

The known weakness is **still present in the standalone current shipped oracle**; calling it historical must not imply it was repaired. Existing M1 acceptance rejects the recorded malformed preflight inputs through its separate witness. No new bypass of that acceptance path is established by the inspected source/fixtures, so this review adds scope documentation rather than silently changing the frozen experimental baseline or attributing old passes to new code.

The landing README already names the exact current signed tag/commit and tells builders to check out v0.1.0-preview.2. That entry remains unchanged. Later documentation commits, including this review, are separate from frozen runtime source and do not redefine its old test results. The recent six canonical-download URL correction is closed and was not repeated.
