package mldsa87

import (
	"bytes"
	"testing"

	internaltest "github.com/theQRL/go-qrllib/crypto/internal/test"
)

// These tests consume the official NIST ACVP sample JSON files for ML-DSA.
// Source: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
//
// The checked-in fixtures live under testdata/acvp as gzip-compressed JSON.

// TestACVPKeyGen verifies that key generation from seed produces byte-exact
// matches against NIST ACVP expected public and secret keys.
func TestACVPKeyGen(t *testing.T) {
	prompt := internaltest.ReadACVPFile[acvpPromptFile](t, "ML-DSA-keyGen-FIPS204", "prompt.json")
	expected := internaltest.ReadACVPFile[acvpExpectedFile](t, "ML-DSA-keyGen-FIPS204", "expectedResults.json")

	tested := 0
	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-DSA-87" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			tested++
			want := wantGroup.test(t, test.TcID)

			seed := internaltest.DecodeACVPHexLength(t, test.Seed, SEED_BYTES)
			privateKey, err := NewPrivateKey(seed)
			if err != nil {
				t.Fatalf("tcId %d: NewPrivateKey: %v", test.TcID, err)
			}

			if got := privateKey.PublicKey().Bytes(); !bytes.Equal(got, internaltest.DecodeACVPHex(t, want.PK)) {
				t.Fatalf("tcId %d: public key mismatch", test.TcID)
			}
			if !bytes.Equal(privateKey.sk[:], internaltest.DecodeACVPHex(t, want.SK)) {
				t.Fatalf("tcId %d: secret key mismatch", test.TcID)
			}
		}
	}
	if tested == 0 {
		t.Fatal("no ML-DSA-87 ACVP keyGen test cases")
	}
}

// TestACVPSigGen verifies that signature generation produces byte-exact
// matches against NIST ACVP expected signatures.
//
// Only external-interface, pure (non-preHash) vectors are tested, as
// go-qrllib implements pure ML-DSA signing. Deterministic vectors use zero rnd;
// randomized vectors use the ACVP-provided rnd.
func TestACVPSigGen(t *testing.T) {
	prompt := internaltest.ReadACVPFile[acvpPromptFile](t, "ML-DSA-sigGen-FIPS204", "prompt.json")
	expected := internaltest.ReadACVPFile[acvpExpectedFile](t, "ML-DSA-sigGen-FIPS204", "expectedResults.json")

	deterministicTested := 0
	randomizedTested := 0
	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-DSA-87" ||
			group.SignatureInterface != "external" ||
			group.PreHash != "pure" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			if group.Deterministic {
				deterministicTested++
			} else {
				randomizedTested++
			}
			want := wantGroup.test(t, test.TcID)

			sk := decodeACVPSecretKey(t, test.SK)
			message := internaltest.DecodeACVPHex(t, test.Message)
			context := internaltest.DecodeACVPHex(t, test.Context)

			rnd := acvpRnd(t, group, test)
			signature := make([]uint8, CRYPTO_BYTES)
			if err := cryptoSignSignatureWithRnd(signature, message, context, &sk, rnd); err != nil {
				t.Fatalf("tcId %d: cryptoSignSignatureWithRnd: %v", test.TcID, err)
			}

			if !bytes.Equal(signature, internaltest.DecodeACVPHex(t, want.Signature)) {
				t.Fatalf("tcId %d: signature mismatch", test.TcID)
			}

			publicKey := publicKeyFromSecretKey(t, &sk)
			if err := Verify(publicKey, message, signature, context); err != nil {
				t.Fatalf("tcId %d: Verify: %v", test.TcID, err)
			}
		}
	}
	if deterministicTested == 0 {
		t.Fatal("no ML-DSA-87 deterministic external pure ACVP sigGen test cases")
	}
	if randomizedTested == 0 {
		t.Fatal("no ML-DSA-87 randomized external pure ACVP sigGen test cases")
	}
}

// TestACVPSigVer verifies signature verification against NIST ACVP expected
// pass/fail results.
//
// Only external-interface, pure (non-preHash) vectors are tested, as
// go-qrllib implements pure ML-DSA verification.
func TestACVPSigVer(t *testing.T) {
	prompt := internaltest.ReadACVPFile[acvpPromptFile](t, "ML-DSA-sigVer-FIPS204", "prompt.json")
	expected := internaltest.ReadACVPFile[acvpExpectedFile](t, "ML-DSA-sigVer-FIPS204", "expectedResults.json")

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

			publicKey, err := NewPublicKey(internaltest.DecodeACVPHex(t, test.PK))
			if err != nil {
				if want.TestPassed {
					t.Fatalf("tcId %d: NewPublicKey: %v", test.TcID, err)
				}
				continue
			}
			message := internaltest.DecodeACVPHex(t, test.Message)
			context := internaltest.DecodeACVPHex(t, test.Context)
			signature := internaltest.DecodeACVPHex(t, test.Signature)

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
	Rnd       string `json:"rnd"`
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

func (f acvpExpectedFile) group(t *testing.T, tgID int) acvpExpectedGroup {
	t.Helper()
	return internaltest.FindACVPByID(t, "test group", tgID, f.TestGroups, func(group acvpExpectedGroup) int {
		return group.TgID
	})
}

func (g acvpExpectedGroup) test(t *testing.T, tcID int) acvpExpectedTest {
	t.Helper()
	return internaltest.FindACVPByID(t, "test case", tcID, g.Tests, func(test acvpExpectedTest) int {
		return test.TcID
	})
}

func decodeACVPSecretKey(t *testing.T, s string) [CRYPTO_SECRET_KEY_BYTES]uint8 {
	t.Helper()
	b := internaltest.DecodeACVPHexLength(t, s, CRYPTO_SECRET_KEY_BYTES)
	var out [CRYPTO_SECRET_KEY_BYTES]uint8
	copy(out[:], b)
	return out
}

func acvpRnd(t *testing.T, group acvpPromptGroup, test acvpPromptTest) [RND_BYTES]uint8 {
	t.Helper()
	if group.Deterministic {
		return [RND_BYTES]uint8{}
	}
	if test.Rnd == "" {
		t.Fatalf("tcId %d: missing randomized ACVP rnd", test.TcID)
	}
	b := internaltest.DecodeACVPHexLength(t, test.Rnd, RND_BYTES)
	var out [RND_BYTES]uint8
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
	publicKey, err := newPublicKeyFromRaw(&pk)
	if err != nil {
		t.Fatalf("parse ACVP public key: %v", err)
	}
	return publicKey
}
