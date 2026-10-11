# cbom-scan

**Find the cryptography in your code, configs, certificates and TLS endpoints. Get a CycloneDX CBOM, a
post-quantum readiness score and a prioritised migration list.**

Every post-quantum migration starts with the same question: *where is our cryptography?* NIST plans to deprecate
RSA and ECC from 2030 and disallow them by 2035, CNSA 2.0 sets earlier dates for national-security systems, and
"harvest now, decrypt later" means data encrypted today with RSA or ECDH is already at risk. You can't migrate
what you can't find.

`cbom-scan` builds that inventory in seconds and keeps it current in CI.

> I recently started making my code public so more people can use it. This is one of the first projects.
> Feedback and issues are welcome.

```
$ cbom-scan ./my-service --tls api.example.com --cbom cbom.json --sarif cbom.sarif --markdown report.md

PQC readiness 0/100 (F)   7 files, 25 algorithms, 5 issues

Broken (6)
  3DES                         config/nginx.conf:4 (+2)
  AES-ECB                      src/legacy.py:10
  MD5                          src/legacy.py:6
  RSA-1024                     src/legacy.py:8
  ...
Quantum-vulnerable (10)
  RSA-2048                     src/server.go:11
  ECDSA-P-384                  src/app.ts:7
  ...
OK (7)
  ML-KEM-768                   src/Crypto.java:8 (+1)
  X25519MLKEM768               config/nginx.conf:5 (+2)

TLS endpoints
  api.example.com:443          TLS 1.3  TLS_AES_256_GCM_SHA384  X25519MLKEM768  post-quantum KEX

Issues
  error   config/nginx.conf:3  Legacy SSL/TLS protocol enabled (SSLv3, TLS 1.0 or 1.1). Require TLS 1.2+, ideally TLS 1.3.
  error   src/server.go:12  TLS certificate verification is disabled, which allows man-in-the-middle attacks.
```

See [examples/](examples/) for the full [Markdown report](examples/sample-report.md), the
[CycloneDX CBOM](examples/sample-cbom.json) and the [SARIF](examples/sample.sarif) produced from the
[sample project](tests/fixtures/sample).

## What it finds

| Source | What it detects |
|---|---|
| **Python** | `hashlib`, `hmac`, `cryptography` (RSA/EC/Ed25519/X25519/DSA/DH, ciphers, modes, AEADs), PyCryptodome, PyJWT, liboqs |
| **Java / Kotlin** | JCA `getInstance(...)` for Cipher, MessageDigest, Signature, KeyPairGenerator, KeyAgreement, Mac, KEM; `ECGenParameterSpec`; Bouncy Castle PQC specs |
| **Go** | `crypto/*` and `x/crypto` imports, `rsa.GenerateKey` sizes, curves, `crypto/mlkem`, `tls.X25519MLKEM768` |
| **JavaScript / TypeScript** | Node `crypto` (hash, HMAC, cipher, sign, key pairs with sizes and curves), WebCrypto, JWT libraries, node-forge |
| **C / C++** | OpenSSL `EVP_*` digests and ciphers, `EVP_PKEY_*`, `RSA_generate_key_ex` sizes, curve NIDs, OpenSSL 3.5 ML-KEM / ML-DSA names |
| **C#, Rust, Ruby, PHP** | .NET `*.Create()` and legacy providers, `MLKem`/`MLDsa`; RustCrypto and ring; Ruby OpenSSL; PHP `openssl_*`, `hash()` |
| **Configs** | nginx, Apache, HAProxy, OpenSSL, sshd: protocol versions, cipher suites (OpenSSL and IANA names), TLS groups, SSH `KexAlgorithms` (incl. `mlkem768x25519`, `sntrup761x25519`) |
| **Certificates and keys** | X.509 (PEM/DER): key type and size, signature algorithm, expiry; PEM/OpenSSH private and public keys; keystores |
| **Live TLS** (`--tls host:port`) | negotiated version, cipher suite and certificate; whether the server agrees to **X25519MLKEM768**; whether it still accepts TLS 1.0/1.1 |
| **Security issues** | legacy SSL/TLS enabled, certificate verification turned off, private keys in the repo, expired or long-lived quantum-vulnerable certificates, insecure RNG for secrets |

Each algorithm gets a status:

| Status | Meaning | Examples |
|---|---|---|
| **Broken** | Weak or deprecated today, quantum or not | MD5, SHA-1, DES, 3DES, RC4, RSA < 2048, ECB mode, DSA |
| **Quantum-vulnerable** | Secure today, broken by Shor's algorithm | RSA, ECDSA, ECDH, EdDSA, X25519, DH |
| **Quantum-weakened** | Grover halves the strength; OK for NIST, below CNSA 2.0 | AES-128, HMAC-SHA1 |
| **OK** | Post-quantum, hybrid, or strong symmetric and hash | ML-KEM, ML-DSA, SLH-DSA, X25519MLKEM768, AES-256, SHA-256+ |

## Install and run

```bash
pipx install git+https://github.com/shubSaurabh/cbom-scan     # or: pip install .
cbom-scan .                                                    # terminal summary
cbom-scan . --cbom cbom.json --markdown report.md              # files to share
cbom-scan --tls api.example.com --tls mail.example.com:465     # endpoints only
cbom-scan . --fail-under 60                                    # CI gate on the score
cbom-scan . --fail-on-broken                                   # CI gate on broken crypto
```

Needs Python 3.10+ and the `cryptography` package. The post-quantum TLS check uses the `openssl` command, version
3.5 or later; without it that column says "unknown".

## Outputs

- **CycloneDX 1.6 CBOM** (`--cbom`): one `cryptographic-asset` component per algorithm, certificate, key and TLS
  endpoint, with `cryptoProperties` (primitive, parameter set, curve, mode, classical and NIST quantum security
  levels, OIDs), certificates linked to their key and signature algorithms, and every occurrence as `evidence`
  with file and line. It validates against the official 1.6 JSON schema and works with CBOM tooling such as
  CBOMkit and Dependency-Track.
- **SARIF 2.1.0** (`--sarif`): upload to GitHub code scanning to see findings inline on pull requests.
- **Markdown** (`--markdown`): a report for people, covering what to fix now, the migration plan per algorithm
  family, PQC already in use, certificates and endpoints.

## Use in GitHub Actions

```yaml
name: crypto-inventory
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  cbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: shubSaurabh/cbom-scan@main
        with:
          path: .
          fail-under: "0"            # raise this as your migration progresses
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: cbom.sarif
      - uses: actions/upload-artifact@v5
        with:
          name: cbom
          path: |
            cbom.json
            cbom-report.md
```

## The readiness score

A simple, explainable number to track progress over time, not a certification:

```
start at 100
-15 per distinct broken algorithm             (max -45)
-10 per quantum-vulnerable family             (max -40)   RSA, ECDSA, ECDH, EdDSA, DH
 -3 per quantum-weakened family               (max  -9)
-10 per error-level security issue            (max -20)
+10 if post-quantum or hybrid crypto is already in use
grades: A >= 90, B >= 75, C >= 60, D >= 40, F below
```

## Limits

This is static, pattern-based analysis, which keeps it fast and dependency-free but has blind spots:

- It sees what is written in code and config. Algorithms chosen at runtime, inside compiled dependencies, or
  inside libraries you call (for example, an SDK that uses RSA internally) are not found. Pair it with a
  dependency SBOM and runtime or network observation for full coverage.
- Key sizes are captured when they appear near the call; otherwise the asset is listed without a size.
- Comment lines are skipped, but strings in docs or tests can still produce matches. Use `--exclude` to skip paths,
  or add `cbom-scan: ignore` in a comment on a line to suppress it (for example, a deliberate `CERT_NONE` in a scanner).

## Development

```bash
PYTHONPATH=src:tests python3 -m unittest discover -s tests -v
```

Tests cover name parsing for every language family, cipher suites and TLS groups, a multi-language sample
project, certificates and keys generated at test time (no secrets are committed), all three output formats,
and the CLI gates.

## Roadmap

- Dependency awareness: map known crypto libraries in lockfiles (pip, npm, Maven, Go modules) to the algorithms they provide
- Binary and container image scanning (OpenSSL and BoringSSL linkage, embedded certificates)
- SSH host and HSM / KMS key inventory
- Diff mode for pull requests: "this change adds RSA-2048"

## Related work

- [IBM sonar-cryptography](https://github.com/IBM/sonar-cryptography) and [CBOMkit](https://github.com/PQCA/cbomkit)
  (PQCA): deep, AST-based Java and Python analysis and the reference CBOM tooling
- [CycloneDX CBOM guide](https://cyclonedx.org/capabilities/cbom/)
- NIST [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) (ML-KEM), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
  (ML-DSA), [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) (SLH-DSA) and
  [IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd) (transition timeline)

`cbom-scan` aims to be the quick, broad first pass: many languages, configs, certificates and live endpoints in
one run, with no build step and no server.

## License

[Business Source License 1.1](LICENSE). You can use, modify and self-host it for free, including in production
inside your own organization. You may not sell it or offer it as a hosted service. Each version becomes
Apache 2.0 four years after it is published. For other licensing, contact the author.

## Author

**Shubham Saurabh**: security architect working on identity, privileged access, data security and post-quantum
cryptography. [GitHub](https://github.com/shubSaurabh)
