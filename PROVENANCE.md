# Verify source and archives

Independently trusted public-key fingerprint:
`SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU`.

From a separately trusted source/verifier, check the checksum signature and selected downloaded archive:
```sh
python tools/verify_downloads.py --directory DOWNLOAD_DIRECTORY --work NEW_VERIFY_DIRECTORY --trusted-fingerprint SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU --archive EXACT_SELECTED_ARCHIVE_FILENAME
```
A key or verifier delivered beside an untrusted archive is not an independent trust root. Exactly one canonical SSH ed25519 public key is accepted; injected principals/extra keys/comments and case-changed fingerprints fail. All actual selected archive hashes are checked after signature validation, including under -O/PYTHONOPTIMIZE.

Signed commits, annotated tags/checksums and exact source manifests establish provenance under that key. They do not establish Windows Authenticode, byte-reproducible builds, a SLSA level, production suitability, exclusive ownership or financial performance. NuGet normalized contentHash excludes signatures and is kept separate from raw signed .nupkg SHA512 in SPDX. Never transfer the private key.
