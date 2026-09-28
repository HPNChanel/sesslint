# Verify a release download

Download checksums, the artifact manifest, the chosen binary or Python package,
its `.sigstore.json` bundle, and `sesslint-provenance.intoto.jsonl` from the same
published GitHub release. Match the version in `sesslint version --json`.
An unsigned local candidate is not a signed release.

PowerShell:

```powershell
Get-FileHash .\sesslint-0.4.1-windows-x86_64.exe -Algorithm SHA256
```

Compare the complete hex digest with its filename's row in `sha256sums.txt`.
On Linux use `sha256sum -c sha256sums.txt --ignore-missing`; on macOS use
`shasum -a 256 <artifact>`. A checksum detects different bytes; publisher
identity requires signature verification too.

With cosign and slsa-verifier installed as separate verification tools, set
`ASSET` to the downloaded filename and `TAG` to its exact published tag:

```sh
cosign verify-blob --bundle "$ASSET.sigstore.json" --certificate-identity "https://github.com/HPNChanel/sesslint/.github/workflows/release.yml@refs/tags/$TAG" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$ASSET"
slsa-verifier verify-artifact "$ASSET" --provenance-path sesslint-provenance.intoto.jsonl --source-uri github.com/HPNChanel/sesslint --source-tag "$TAG"
```

In PowerShell use `$Asset = 'actual-filename'` and `$Tag = 'actual-tag'`;
the two commands above work on single lines using `$Asset` and `$Tag`.
Do not ignore a mismatch or substitute a broader certificate identity.
Use the synthetic walkthrough after verification before checking your own files.

Sigstore signatures are distinct from Authenticode and macOS notarization.
Operating-system publisher trust is not implied unless separately documented
for the asset. The SessLint runtime itself remains offline and requires none
of these verification tools during ordinary checks or repairs.
