package mlkem1024

import (
	"bytes"
	"errors"
	"testing"

	internaltest "github.com/theQRL/go-qrllib/crypto/internal/test"
)

// These tests consume the official NIST ACVP sample JSON files for ML-KEM.
// Source: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
//
// The checked-in fixtures live under testdata/acvp as gzip-compressed JSON.

func TestACVPJSONKeyGen(t *testing.T) {
	prompt := internaltest.ReadACVPFile[acvpPromptFile](t, "ML-KEM-keyGen-FIPS203", "prompt.json")
	expected := internaltest.ReadACVPFile[acvpExpectedFile](t, "ML-KEM-keyGen-FIPS203", "expectedResults.json")

	tested := 0
	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-KEM-1024" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			tested++
			want := wantGroup.test(t, test.TcID)

			d := internaltest.DecodeACVPHex32(t, test.D)
			z := internaltest.DecodeACVPHex32(t, test.Z)

			var seed [SeedSize]byte
			copy(seed[:32], d[:])
			copy(seed[32:], z[:])

			dk, err := NewDecapsulationKey(seed[:])
			if err != nil {
				t.Fatalf("tcId %d: NewDecapsulationKey: %v", test.TcID, err)
			}

			if got := dk.EncapsulationKey().Bytes(); !bytes.Equal(got, internaltest.DecodeACVPHex(t, want.EK)) {
				t.Fatalf("tcId %d: encapsulation key mismatch", test.TcID)
			}
			if got := expandedDecapsulationKeyBytes(dk); !bytes.Equal(got, internaltest.DecodeACVPHex(t, want.DK)) {
				t.Fatalf("tcId %d: expanded decapsulation key mismatch", test.TcID)
			}
		}
	}
	if tested == 0 {
		t.Fatal("no ML-KEM-1024 ACVP keyGen test cases")
	}
}

func TestACVPJSONEncapsulation(t *testing.T) {
	prompt := internaltest.ReadACVPFile[acvpPromptFile](t, "ML-KEM-encapDecap-FIPS203", "prompt.json")
	expected := internaltest.ReadACVPFile[acvpExpectedFile](t, "ML-KEM-encapDecap-FIPS203", "expectedResults.json")

	tested := 0
	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-KEM-1024" || group.Function != "encapsulation" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			tested++
			want := wantGroup.test(t, test.TcID)

			ek, err := NewEncapsulationKey(internaltest.DecodeACVPHex(t, test.EK))
			if err != nil {
				t.Fatalf("tcId %d: NewEncapsulationKey: %v", test.TcID, err)
			}
			m := internaltest.DecodeACVPHex32(t, test.M)
			var ct [CiphertextSize]byte
			gotK := encapsulateTo(&ct, ek, &m)

			if !bytes.Equal(gotK, internaltest.DecodeACVPHex(t, want.K)) {
				t.Fatalf("tcId %d: shared key mismatch", test.TcID)
			}
			if !bytes.Equal(ct[:], internaltest.DecodeACVPHex(t, want.C)) {
				t.Fatalf("tcId %d: ciphertext mismatch", test.TcID)
			}
		}
	}
	if tested == 0 {
		t.Fatal("no ML-KEM-1024 ACVP encapsulation test cases")
	}
}

func TestACVPJSONDecapsulation(t *testing.T) {
	prompt := internaltest.ReadACVPFile[acvpPromptFile](t, "ML-KEM-encapDecap-FIPS203", "prompt.json")
	expected := internaltest.ReadACVPFile[acvpExpectedFile](t, "ML-KEM-encapDecap-FIPS203", "expectedResults.json")

	tested := 0
	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-KEM-1024" || group.Function != "decapsulation" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			tested++
			want := wantGroup.test(t, test.TcID)
			dk, err := newDecapsulationKeyFromExpandedACVP(internaltest.DecodeACVPHex(t, test.DK))
			if err != nil {
				t.Fatalf("tcId %d: decapsulation key: %v", test.TcID, err)
			}

			gotK, err := dk.Decapsulate(internaltest.DecodeACVPHex(t, test.C))
			if err != nil {
				t.Fatalf("tcId %d: Decapsulate: %v", test.TcID, err)
			}
			if !bytes.Equal(gotK, internaltest.DecodeACVPHex(t, want.K)) {
				t.Fatalf("tcId %d: shared key mismatch", test.TcID)
			}
		}
	}
	if tested == 0 {
		t.Fatal("no ML-KEM-1024 ACVP decapsulation test cases")
	}
}

func TestACVPJSONDecapsulationKeyCheck(t *testing.T) {
	prompt := internaltest.ReadACVPFile[acvpPromptFile](t, "ML-KEM-encapDecap-FIPS203", "prompt.json")
	expected := internaltest.ReadACVPFile[acvpExpectedFile](t, "ML-KEM-encapDecap-FIPS203", "expectedResults.json")

	tested := 0
	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-KEM-1024" || group.Function != "decapsulationKeyCheck" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			tested++
			want := wantGroup.test(t, test.TcID)

			_, err := newDecapsulationKeyFromExpandedACVP(internaltest.DecodeACVPHex(t, test.DK))
			if got := err == nil; got != want.TestPassed {
				t.Fatalf("tcId %d: validation result = %t, want %t", test.TcID, got, want.TestPassed)
			}
		}
	}
	if tested == 0 {
		t.Fatal("no ML-KEM-1024 ACVP decapsulationKeyCheck test cases")
	}
}

func TestACVPJSONEncapsulationKeyCheck(t *testing.T) {
	prompt := internaltest.ReadACVPFile[acvpPromptFile](t, "ML-KEM-encapDecap-FIPS203", "prompt.json")
	expected := internaltest.ReadACVPFile[acvpExpectedFile](t, "ML-KEM-encapDecap-FIPS203", "expectedResults.json")

	tested := 0
	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-KEM-1024" || group.Function != "encapsulationKeyCheck" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			tested++
			want := wantGroup.test(t, test.TcID)

			_, err := NewEncapsulationKey(internaltest.DecodeACVPHex(t, test.EK))
			if got := err == nil; got != want.TestPassed {
				t.Fatalf("tcId %d: validation result = %t, want %t", test.TcID, got, want.TestPassed)
			}
		}
	}
	if tested == 0 {
		t.Fatal("no ML-KEM-1024 ACVP encapsulationKeyCheck test cases")
	}
}

type acvpPromptFile struct {
	TestGroups []acvpPromptGroup `json:"testGroups"`
}

type acvpPromptGroup struct {
	TgID         int              `json:"tgId"`
	ParameterSet string           `json:"parameterSet"`
	Function     string           `json:"function"`
	Tests        []acvpPromptTest `json:"tests"`
}

type acvpPromptTest struct {
	TcID int    `json:"tcId"`
	D    string `json:"d"`
	Z    string `json:"z"`
	EK   string `json:"ek"`
	DK   string `json:"dk"`
	M    string `json:"m"`
	C    string `json:"c"`
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
	EK         string `json:"ek"`
	DK         string `json:"dk"`
	C          string `json:"c"`
	K          string `json:"k"`
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

// expandedDecapsulationKeyBytes returns the ACVP/NIST expanded decapsulation key form.
func expandedDecapsulationKeyBytes(dk *DecapsulationKey) []byte {
	b := make([]byte, 0, k*encodingSize12+EncapsulationKeySize+64)
	var encoded [encodingSize12]byte
	for i := range dk.s {
		byteEncode12(&encoded, &dk.s[i])
		b = append(b, encoded[:]...)
	}
	b = append(b, dk.EncapsulationKey().Bytes()...)
	b = append(b, dk.h[:]...)
	b = append(b, dk.z[:]...)
	return b
}

func newDecapsulationKeyFromExpandedACVP(b []byte) (*DecapsulationKey, error) {
	const expandedSize = k*encodingSize12 + EncapsulationKeySize + 64
	if len(b) != expandedSize {
		return nil, errors.New("invalid expanded decapsulation key length")
	}

	dk := &DecapsulationKey{}
	for i := range dk.s {
		if err := byteDecode12(&dk.s[i], (*[encodingSize12]byte)(b[:encodingSize12])); err != nil {
			return nil, err
		}
		b = b[encodingSize12:]
	}

	ek, err := NewEncapsulationKey(b[:EncapsulationKeySize])
	if err != nil {
		return nil, err
	}
	dk.h = ek.h
	dk.encryptionKey = ek.encryptionKey
	b = b[EncapsulationKeySize:]

	if !bytes.Equal(dk.h[:], b[:32]) {
		return nil, errors.New("expanded decapsulation key has inconsistent H(ek)")
	}
	b = b[32:]
	copy(dk.z[:], b[:32])

	return dk, nil
}
