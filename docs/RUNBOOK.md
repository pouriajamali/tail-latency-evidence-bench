# Runbook and review

Start with the native CLI --version, archive manifest and provenance; then read summary status, planned/attempted/admitted/completed/rejected/censored counts; then inspect ranks with their completed denominator. Run tools/oracle.py on retained raw files. Do not treat COMPLETE accounting as 100% successful work.

On INCOMPLETE, retain evidence and reason. A raw-cap rejection has no samples or quantiles. Do not silently increase the limit, change power plans/timer resolution/security, remove missing work or retry until a faster-looking result appears. Use fresh output paths and report the original failed run beside any new run.

To reproduce, preserve source commit/archive SHA, config/seed/logical schedule hash, raw CSV, summary, oracle receipt, clock/runtime/OS/CPU/virtualization/power metadata. Do not subtract clock-read benchmark means or combine traced/untraced and warmup/measured samples. Inspectable synthetic results may be shared after the coordinated publication gate; local traces and host scratch stay private by default.

Review slices: scheduling/admission/cutoff; conservation and independent ranks; raw-cap and corrupted-data counterexamples; package/runtime licenses/provenance. The eight Python regressions use an actual run and fail modified inputs without timing thresholds. Source, local runtime and public CI/download evidence are separately named.

Bounded defaults intentionally omit automatic parameter tuning or an optimization winner. Native AOT, alternative queues or external feeds need a separately reviewed experiment; they are not silently enabled here.
