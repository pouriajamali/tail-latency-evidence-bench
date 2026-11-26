# Tail offline oracle v0.1.0-preview.1

[Download the Python ZIP](./tail-latency-evidence-oracle-v0.1.0-preview.1.zip) ·
[SHA256SUMS.txt](./SHA256SUMS.txt) ·
[checksum signature](./SHA256SUMS.txt.sig) ·
[public signing key](./SIGNING-PUBLIC-KEY.pub)

The ZIP contains the updated Python oracle, demo wrapper, regression tests
and usage instructions. It needs Python 3.12 and no third-party Python
packages. Source commit:
[`942f1ab46688`](https://github.com/pouriajamali/tail-latency-evidence-bench/commit/942f1ab466887e66607d3e33a013572a2d8d221f).

Check the SSH signature on the exact checksum file with the independently
trusted portfolio key, then check the ZIP's SHA256 before extraction.
Follow the verification commands in the
[provenance guide](https://github.com/pouriajamali/tail-latency-evidence-bench/blob/942f1ab466887e66607d3e33a013572a2d8d221f/PROVENANCE.md)
using the four files linked above. The expected key fingerprint is
`SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU`.

Run the wrapper from the ZIP with the verified
[v0.1.0-preview.2 native executable](https://github.com/pouriajamali/tail-latency-evidence-bench/releases/tag/v0.1.0-preview.2)
or use the oracle by itself against saved run files. This ZIP contains no
native executable. The original preview.2 archives keep their historical tools.

The actual Windows preview.2 executable completed six synthetic cases with
the new wrapper. Its 19 oracle tests passed. The packaged oracle also
accepted the six retained Windows/Linux fixture cases and rejected all 24
negative fixtures. These are local correctness checks. A native Linux run
was outside this package check.
