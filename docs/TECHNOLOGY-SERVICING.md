# .NET 10 servicing decision - 2026-11-20

Status: NATIVE_SDK_QUALIFICATION_ACCEPTED_BUILD_VALIDATION_PENDING. This decision does not reopen delivered M1.

Microsoft's current .NET 10 release metadata identifies SDK 10.0.404/runtime 10.0.15, released 2026-11-10, as active LTS security servicing. The prepared change retains net10.0 and C#14. Both .NET 10 LTS and .NET 11 STS currently list 2028-11-14 end of support; no required .NET 11-only capability justifies a major migration here. Existing BenchmarkDotNet 0.15.8, xUnit v3 4.0.3 and dotnet-trace 10.0.750501 are retained, excluded from the shipped BCL-only graph. No new benchmark, trace or performance claim is planned.

Official references, observed 2026-11-20:

- [.NET 10 release metadata](https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/10.0/releases.json)
- [.NET support lifecycle](https://dotnet.microsoft.com/en-us/platform/support/policy)
- [.NET 10 supported operating systems](https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.md)
- [Windows installation/support table](https://learn.microsoft.com/en-us/dotnet/core/install/windows#supported-versions)

## Scope and retained evidence

Only SDK/runtime/package-version pins, the packaging/checking runtime identities and additive exact notice-source records change. Product C# source, API/output contracts, package locks, diagnostic dependencies, loader/PKI guards, known signing identity, M1 source/data/counterexamples and prior preview/tag/assets remain unchanged. v0.1.0-preview.2 is a prospective source version; no such release, build or package is claimed.

The sealed 10.0.15 notice and normalized/raw package identities are reused as data. Historical signature results retain their historical scope. Actual package metadata, consuming bytes, raw signed archive identity, shipped dependency graph and notices must still pass the established packager. No current SDK, signature, host or provider admission is inherited from another project.

## Required bounded execution and blocker

Use the existing canonical lease and project-specific controller, with unchanged approved caps. Start the fresh clock only after atomic claim; preserve exact owner/process-birth/token on release. Validate source/host/PID/membership/caps and measured own resource use. Test only changed servicing requirements and the new binaries; reuse closed M1 and healthy diagnostics. No Actions event, trust/protection/global setting change, controller bypass or foreign lease reset is permitted.

The observed Windows host reports 26H2/build 26300.10075. The official table does not establish support for that host. Under the owner's explicit local LAB decision, it is observed experimental with `formalVendorSupport=NOT_CONFIRMED`; its actual version is never renamed or promoted to supported=true. Separate Linux evidence records Ubuntu24.04. No Linux result certifies Windows and no producer input is consumer admission.

Producer04 delivered a data-only, contract-bound SDK10/runtime15 handoff. Historical sealed SDK inventory/materialization, normalized/raw identities, notices and signature facts retain their original scope. Current advisory metadata changed and is explicitly distinguished from historical signature/closure/current-trust unknowns. Consumer11 verifies actual source/input/native child identity, caps, clock and own lease; standard native package signature checks still apply before runtime publication.

Native SDK --info qualification completed once per OS. The Windows adapter initially stopped before any Job/worker on a stale copied bridge pin. Its actual frozen M1 bridge and consumer-profile hashes agreed; exact-own pre-child recovery released the retained lease, and the adapter pin was corrected to those unchanged bytes. No M1 source or security guard changed. The first NuGet verification encountered missing Windows APPDATA/LOCALAPPDATA in the isolated child environment; NuGet's official source reads these variables for its settings paths. Task-local user/cache directories and read-only standard ProgramFiles paths correct that setup without global config/trust changes. Its failure is retained; successful SDK qualification is not repeated.

The fixed adapter exposes only qualification, affected restore/build/test, runtime verification, new rejection controls and native packaging/checking. It reuses the existing kernel witness and Job bridge, with post-claim300/work270/terminal30, role20/qualification60/native45/controller60, Windows512MiB/16/CPU1000/affinity<=2 and Linux512MiB/swap0/tasks64/CPU200%. Direct consuming guards retain64MiB/256-file bounds and explicit no-global-closure scope. Restore/test/package I/O, peak memory/processes/CPU and terminal identities are recorded. A source-bound accepted locked restore and unchanged assets may be reused by packaging; it never silently skips the prerequisite or repeats it for reporting.

Build/unit/package/signature/download validation is separate and remains pending until actual receipts exist. CI is NOT_RUN_OWNER_PROHIBITED. No Actions, M1 experiment, healthy benchmark, trace, loader/PKI research, global trust/protection change, new infrastructure or production/performance/security claim follows.

The pure receiving controls reject eight malformed/version/root/borrowed-admission/support inputs without SDK execution. Additional actual consumer negatives test wrong source, wrong canonical owner and wrong SDK entry bytes under the native Job/cgroup; they never execute a rejected SDK or count as M1 counterexamples.

The native Linux NuGet verifier reached its unchanged20-second role ceiling; the result is retained as UNKNOWN/timeout and the collected own systemd scope ended/released. No chain/root/revocation/closure setting or deadline is weakened. The fixed Windows data-signature role may verify the exact platform-neutral Linux runtime archive with its actual native NuGet verifier, normalized identity and unchanged known raw archive guard. That is package-data evidence, not a Linux-verifier or Linux-host admission. Native Linux compatibility/build/package tests remain independent requirements.

Both operating systems use one task-owned locked-restore package cache, with serialized own controllers and the same physical E workspace. Windows produces the initial cache through ordinary locked restore; Linux still restores its own assets and performs its own build/tests against those inputs. Accepted downloads/inputs are reused rather than fetched or bootstrapped for reporting. SDK command start/birth/membership is recorded before waiting, including failed commands. SDK/test telemetry is opted out only in the owned child environment; no system setting is changed.

The first Windows restore reached the unchanged60-second controller bound while its SDK-created cache contained48 files and an incomplete runtime extraction. No assets/locked-restore success was claimed; the Job was terminated to active0 and only its own lease released. The incomplete E cache is preserved. The causal retry uses only task-private authorized C scratch for NuGet packages/temp/HTTP data, mapped to the same physical files from Linux. Source, SDK roots and the canonical lease remain on E. No package metadata is forged, signature check disabled, source lock edited or timeout/cap raised. Actual before/after task scratch, proof and build-output sizes are recorded against1GiB/8MiB and the unchanged consuming-byte guards.

Packaging copies support files only from the exact tracked Git inventory. The new M1 tooling has ignored local inputs in its working tree; those private input archives/frames/caches must not be copied recursively into a new distributable. Original M1 inputs and published assets remain untouched. Native package inspection verifies the produced support inventory and all payload bytes.
