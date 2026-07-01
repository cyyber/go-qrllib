package mldsa87

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// These tests consume the official NIST ACVP sample JSON files for ML-DSA.
// Source: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
//
// The checked-in fixtures live under testdata/acvp as gzip-compressed JSON.

// TestACVPKeyGen verifies that key generation from seed produces byte-exact
// matches against NIST ACVP expected public and secret keys.
func TestACVPKeyGen(t *testing.T) {
	prompt := readACVPFile[acvpPromptFile](t, "ML-DSA-keyGen-FIPS204", "prompt.json")
	expected := readACVPFile[acvpExpectedFile](t, "ML-DSA-keyGen-FIPS204", "expectedResults.json")

	tested := 0
	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-DSA-87" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			tested++
			want := wantGroup.test(t, test.TcID)

			seed := decodeACVPHexLength(t, test.Seed, SEED_BYTES)
			privateKey, err := NewPrivateKey(seed)
			if err != nil {
				t.Fatalf("tcId %d: NewPrivateKey: %v", test.TcID, err)
			}

			if got := privateKey.PublicKey().Bytes(); !bytes.Equal(got, decodeACVPHex(t, want.PK)) {
				t.Fatalf("tcId %d: public key mismatch", test.TcID)
			}
			if !bytes.Equal(privateKey.sk[:], decodeACVPHex(t, want.SK)) {
				t.Fatalf("tcId %d: secret key mismatch", test.TcID)
			}
		}
	}
	if tested == 0 {
		t.Fatal("no ML-DSA-87 ACVP keyGen test cases")
	}
}

// TestACVPSigGen verifies that deterministic signature generation produces
// byte-exact matches against NIST ACVP expected signatures.
//
// Only deterministic, external-interface, pure (non-preHash) vectors are
// tested, as go-qrllib implements pure ML-DSA signing.
func TestACVPSigGen(t *testing.T) {
	prompt := readACVPFile[acvpPromptFile](t, "ML-DSA-sigGen-FIPS204", "prompt.json")
	expected := readACVPFile[acvpExpectedFile](t, "ML-DSA-sigGen-FIPS204", "expectedResults.json")

	tested := 0
	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-DSA-87" ||
			!group.Deterministic ||
			group.SignatureInterface != "external" ||
			group.PreHash != "pure" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			tested++
			want := wantGroup.test(t, test.TcID)

			sk := decodeACVPSecretKey(t, test.SK)
			message := decodeACVPHex(t, test.Message)
			context := decodeACVPHex(t, test.Context)

			var rnd [RND_BYTES]uint8 // zero - FIPS 204 deterministic mode
			signature := make([]uint8, CRYPTO_BYTES)
			if err := cryptoSignSignatureWithRnd(signature, message, context, &sk, rnd); err != nil {
				t.Fatalf("tcId %d: cryptoSignSignatureWithRnd: %v", test.TcID, err)
			}

			if !bytes.Equal(signature, decodeACVPHex(t, want.Signature)) {
				t.Fatalf("tcId %d: signature mismatch", test.TcID)
			}

			publicKey := publicKeyFromSecretKey(t, &sk)
			if err := Verify(publicKey, message, signature, context); err != nil {
				t.Fatalf("tcId %d: Verify: %v", test.TcID, err)
			}
		}
	}
	if tested == 0 {
		t.Fatal("no ML-DSA-87 deterministic external pure ACVP sigGen test cases")
	}
}

// TestACVPSigVer verifies signature verification against NIST ACVP expected
// pass/fail results.
//
// Only external-interface, pure (non-preHash) vectors are tested, as
// go-qrllib implements pure ML-DSA verification.
func TestACVPSigVer(t *testing.T) {
	prompt := readACVPFile[acvpPromptFile](t, "ML-DSA-sigVer-FIPS204", "prompt.json")
	expected := readACVPFile[acvpExpectedFile](t, "ML-DSA-sigVer-FIPS204", "expectedResults.json")

	tested := 0
	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-DSA-87" ||
			group.SignatureInterface != "external" ||
			group.PreHash != "pure" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			tested++
			want := wantGroup.test(t, test.TcID)

			publicKey, err := NewPublicKey(decodeACVPHex(t, test.PK))
			if err != nil {
				if want.TestPassed {
					t.Fatalf("tcId %d: NewPublicKey: %v", test.TcID, err)
				}
				continue
			}
			message := decodeACVPHex(t, test.Message)
			context := decodeACVPHex(t, test.Context)
			signature := decodeACVPHex(t, test.Signature)

			got := Verify(publicKey, message, signature, context) == nil
			if got != want.TestPassed {
				t.Fatalf("tcId %d: verification result = %t, want %t", test.TcID, got, want.TestPassed)
			}
		}
	}
	if tested == 0 {
		t.Fatal("no ML-DSA-87 external pure ACVP sigVer test cases")
	}
}

type acvpPromptFile struct {
	TestGroups []acvpPromptGroup `json:"testGroups"`
}

type acvpPromptGroup struct {
	TgID               int              `json:"tgId"`
	ParameterSet       string           `json:"parameterSet"`
	Deterministic      bool             `json:"deterministic"`
	SignatureInterface string           `json:"signatureInterface"`
	PreHash            string           `json:"preHash"`
	Tests              []acvpPromptTest `json:"tests"`
}

type acvpPromptTest struct {
	TcID      int    `json:"tcId"`
	Seed      string `json:"seed"`
	PK        string `json:"pk"`
	SK        string `json:"sk"`
	Message   string `json:"message"`
	Context   string `json:"context"`
	Signature string `json:"signature"`
}

type acvpExpectedFile struct {
	TestGroups []acvpExpectedGroup `json:"testGroups"`
}

type acvpExpectedGroup struct {
	TgID  int                `json:"tgId"`
	Tests []acvpExpectedTest `json:"tests"`
}

type acvpExpectedTest struct {
	TcID       int    `json:"tcId"`
	PK         string `json:"pk"`
	SK         string `json:"sk"`
	Signature  string `json:"signature"`
	TestPassed bool   `json:"testPassed"`
}

func readACVPFile[T any](t *testing.T, suite, name string) T {
	t.Helper()

	path := filepath.Join("testdata", "acvp", suite, name)
	b, path := readACVPBytes(t, path)

	var f T
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse ACVP JSON %q: %v", path, err)
	}
	return f
}

func readACVPBytes(t *testing.T, path string) ([]byte, string) {
	t.Helper()

	b, err := os.ReadFile(path)
	if err == nil {
		return b, path
	}

	gzPath := path + ".gz"
	f, err := os.Open(gzPath)
	if err != nil {
		t.Fatalf("read ACVP JSON %q: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("open compressed ACVP JSON %q: %v", gzPath, err)
	}
	defer func() { _ = gz.Close() }()

	b, err = io.ReadAll(gz)
	if err != nil {
		t.Fatalf("read compressed ACVP JSON %q: %v", gzPath, err)
	}
	return b, gzPath
}

func (f acvpExpectedFile) group(t *testing.T, tgID int) acvpExpectedGroup {
	t.Helper()
	for _, group := range f.TestGroups {
		if group.TgID == tgID {
			return group
		}
	}
	t.Fatalf("missing ACVP test group %d", tgID)
	return acvpExpectedGroup{}
}

func (g acvpExpectedGroup) test(t *testing.T, tcID int) acvpExpectedTest {
	t.Helper()
	for _, test := range g.Tests {
		if test.TcID == tcID {
			return test
		}
	}
	t.Fatalf("missing ACVP test case %d", tcID)
	return acvpExpectedTest{}
}

func decodeACVPHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode ACVP hex: %v", err)
	}
	return b
}

func decodeACVPHexLength(t *testing.T, s string, size int) []byte {
	t.Helper()
	b := decodeACVPHex(t, s)
	if len(b) != size {
		t.Fatalf("decode ACVP hex length = %d, want %d", len(b), size)
	}
	return b
}

func decodeACVPSecretKey(t *testing.T, s string) [CRYPTO_SECRET_KEY_BYTES]uint8 {
	t.Helper()
	b := decodeACVPHexLength(t, s, CRYPTO_SECRET_KEY_BYTES)
	var out [CRYPTO_SECRET_KEY_BYTES]uint8
	copy(out[:], b)
	return out
}

func publicKeyFromSecretKey(t *testing.T, sk *[CRYPTO_SECRET_KEY_BYTES]uint8) *PublicKey {
	t.Helper()

	var rho [SEED_BYTES]uint8
	var tr [TR_BYTES]uint8
	var key [SEED_BYTES]uint8
	var t0 polyVecK
	var s1 polyVecL
	var s2 polyVecK
	unpackSk(&rho, &tr, &key, &t0, &s1, &s2, sk)

	var s1hat polyVecL
	var mat [K]polyVecL
	var t1 polyVecK
	s1hat = s1
	polyVecLNTT(&s1hat)
	if err := polyVecMatrixExpand(&mat, &rho); err != nil {
		t.Fatalf("expand ACVP public key matrix: %v", err)
	}
	polyVecMatrixPointWiseMontgomery(&t1, &mat, &s1hat)
	polyVecKReduce(&t1)
	polyVecKInvNTTToMont(&t1)
	polyVecKAdd(&t1, &t1, &s2)
	polyVecKCAddQ(&t1)

	var t0Discard polyVecK
	polyVecKPower2Round(&t1, &t0Discard, &t1)

	var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
	packPk(&pk, rho, &t1)
	return &PublicKey{raw: pk}
}
