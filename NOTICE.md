# Attribution and licenses

Original fresh synthetic code: Copyright (c) 2026 Pouria Jamali, MIT (LICENSE).

Provenance/notice/archive helpers and the tiny public signed verifier fixture are adapted from the public MIT [Fenced Shard Ownership Lab](https://github.com/pouriajamali/fenced-shard-ownership-lab/tree/7c853fde7bf2aeab9bf60f6b6e979cb17738d802). Retain its original MIT notice. Canonical single-key verification remains active under Python optimization; tests create their own disposable attacker keys privately. No original signing private key is copied or bundled.

The self-contained CLI ships one Microsoft.NETCore.App.Runtime RID pack, MIT plus the runtime's complete original third-party notices/copyright. Exact runtime/license/raw-archive pins are in vendor/notices/NOTICE-SOURCES.json. DEPENDENCIES.json and SPDX describe this shipped NuGet/runtime graph, not every external OS component.

BenchmarkDotNet 0.15.8, dotnet-trace 10.0.750501 and xUnit v3 4.0.3 retain their upstream licenses as source build/test references; their binaries are not bundled in the runtime archive. Source locks/tool manifest pin them. No histogram port, account/feed data or private/shared asset is transferred. MIT applies to original code and does not relabel dependencies or establish exclusive ownership.
