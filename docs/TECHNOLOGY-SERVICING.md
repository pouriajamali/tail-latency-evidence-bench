# .NET 10 servicing decision - 2026-11-20

Status: SOURCE_PREPARED_RUNTIME_UNVALIDATED. This decision does not reopen delivered M1.

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

The observed Windows host reports 26H2/build 26300.10075. Microsoft's current .NET 10 table lists Windows 11 26H1/25H2/24H2 and selected older editions, not 26H2. Treat supported Windows SDK execution as unestablished. The owner previously reported no other authorized Windows runner. A supported, already authorized Windows native build route with binding to this workspace is the external requirement. An existing Linux route can proceed only with its own current binding and caps; it cannot satisfy native Windows packaging by transferring another project's admission or relabeling a cross-built local candidate.

Until that route and independent SDK consuming binding exist, native SDK/build/test/package work is NOT_RUN, CI is NOT_RUN_OWNER_PROHIBITED, no new runtime is released and the existing verified preview remains the download target. This records a real delivery gap, not a successful upgrade.
