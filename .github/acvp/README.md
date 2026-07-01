# NIST ACVP Test Vector Verification

go-qrllib verifies ML-DSA-87 against official NIST ACVP (Automated
Cryptographic Validation Protocol) sample vectors from:

https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files

## How It Works

The ML-DSA ACVP fixtures are checked in under
`crypto/internal/mldsa87/testdata/acvp` as gzip-compressed JSON. This matches
the ML-KEM fixture approach and makes the tests available during normal local
test runs without external setup.

`crypto/internal/mldsa87/acvp_test.go` reads the original NIST `prompt.json`
and `expectedResults.json` files directly, filters them to ML-DSA-87, and
compares byte-exact output.

## What's Tested

| Test | Vectors | Description |
|------|---------|-------------|
| `TestACVPKeyGen` | 25 | Seed -> (pk, sk) matches NIST expected output |
| `TestACVPSigGen` | 15 | sk + message + context -> signature matches NIST expected output |
| `TestACVPSigVer` | 15 | pk + message + context + signature -> pass/fail matches NIST expected output |

Only deterministic, external-interface, pure (non-preHash) signature vectors
are tested. go-qrllib's public ML-DSA-87 signing API is hedged by default per
FIPS 204, so fixed ACVP signatures are reproduced through the same internal
signing core with `RND_BYTES` set to zero for FIPS 204 deterministic mode.

## Running Locally

```bash
go test -v -run TestACVP ./crypto/internal/mldsa87/
```

The ACVP tests also run as part of:

```bash
go test ./...
```

## Refreshing Fixtures

```bash
base=https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files
for suite in ML-DSA-keyGen-FIPS204 ML-DSA-sigGen-FIPS204 ML-DSA-sigVer-FIPS204; do
  mkdir -p "crypto/internal/mldsa87/testdata/acvp/$suite"
  for name in prompt.json expectedResults.json; do
    curl -fsSL "$base/$suite/$name" |
      gzip -9 > "crypto/internal/mldsa87/testdata/acvp/$suite/$name.gz"
  done
done
```

After refreshing, run:

```bash
go test -v -run TestACVP ./crypto/internal/mldsa87/
```

## Other Algorithms

| Algorithm | ACVP Vectors Available? | Compatible? | Reason |
|-----------|------------------------|-------------|--------|
| **ML-DSA-87** | Yes (ML-DSA FIPS 204) | Yes | Direct match |
| **SPHINCS+** | No (SLH-DSA FIPS 205 only) | No | go-qrllib implements SPHINCS+ SHAKE-256s-robust (pre-FIPS submission), while FIPS 205 standardized the simple variant |
| **XMSS** | No | N/A | XMSS (RFC 8391) is not an ACVP-validated algorithm |
