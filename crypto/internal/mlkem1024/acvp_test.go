package mlkem1024

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// These tests consume the official NIST ACVP sample JSON files for ML-KEM.
// Source: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
//
// The checked-in fixtures live under testdata/acvp as gzip-compressed JSON.

func TestACVPJSONKeyGen(t *testing.T) {
	prompt := readACVPFile(t, "ML-KEM-keyGen-FIPS203", "prompt.json")
	expected := readACVPFile(t, "ML-KEM-keyGen-FIPS203", "expectedResults.json")

	tested := 0
	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-KEM-1024" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			tested++
			want := wantGroup.test(t, test.TcID)

			seed := append(decodeACVPHex(t, test.D), decodeACVPHex(t, test.Z)...)
			dk, err := NewDecapsulationKey(seed)
			if err != nil {
				t.Fatalf("tcId %d: NewDecapsulationKey: %v", test.TcID, err)
			}

			if got := dk.EncapsulationKey().Bytes(); !bytes.Equal(got, decodeACVPHex(t, want.EK)) {
				t.Fatalf("tcId %d: encapsulation key mismatch", test.TcID)
			}
			if got := expandedDecapsulationKeyBytes(dk); !bytes.Equal(got, decodeACVPHex(t, want.DK)) {
				t.Fatalf("tcId %d: expanded decapsulation key mismatch", test.TcID)
			}
		}
	}
	if tested == 0 {
		t.Fatal("no ML-KEM-1024 ACVP keyGen test cases")
	}
}

func TestACVPJSONEncapsulation(t *testing.T) {
	prompt := readACVPFile(t, "ML-KEM-encapDecap-FIPS203", "prompt.json")
	expected := readACVPFile(t, "ML-KEM-encapDecap-FIPS203", "expectedResults.json")

	tested := 0
	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-KEM-1024" || group.Function != "encapsulation" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			tested++
			want := wantGroup.test(t, test.TcID)

			ek, err := NewEncapsulationKey(decodeACVPHex(t, test.EK))
			if err != nil {
				t.Fatalf("tcId %d: NewEncapsulationKey: %v", test.TcID, err)
			}
			m := decodeACVPHex32(t, test.M)
			var ct [CiphertextSize]byte
			gotK := encapsulateTo(&ct, ek, &m)

			if !bytes.Equal(gotK, decodeACVPHex(t, want.K)) {
				t.Fatalf("tcId %d: shared key mismatch", test.TcID)
			}
			if !bytes.Equal(ct[:], decodeACVPHex(t, want.C)) {
				t.Fatalf("tcId %d: ciphertext mismatch", test.TcID)
			}
		}
	}
	if tested == 0 {
		t.Fatal("no ML-KEM-1024 ACVP encapsulation test cases")
	}
}

func TestACVPJSONDecapsulation(t *testing.T) {
	prompt := readACVPFile(t, "ML-KEM-encapDecap-FIPS203", "prompt.json")
	expected := readACVPFile(t, "ML-KEM-encapDecap-FIPS203", "expectedResults.json")

	tested := 0
	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-KEM-1024" || group.Function != "decapsulation" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			tested++
			want := wantGroup.test(t, test.TcID)
			dk := newDecapsulationKeyFromExpandedACVP(t, decodeACVPHex(t, test.DK))

			gotK, err := dk.Decapsulate(decodeACVPHex(t, test.C))
			if err != nil {
				t.Fatalf("tcId %d: Decapsulate: %v", test.TcID, err)
			}
			if !bytes.Equal(gotK, decodeACVPHex(t, want.K)) {
				t.Fatalf("tcId %d: shared key mismatch", test.TcID)
			}
		}
	}
	if tested == 0 {
		t.Fatal("no ML-KEM-1024 ACVP decapsulation test cases")
	}
}

func TestACVPJSONDecapsulationKeyCheck(t *testing.T) {
	prompt := readACVPFile(t, "ML-KEM-encapDecap-FIPS203", "prompt.json")
	expected := readACVPFile(t, "ML-KEM-encapDecap-FIPS203", "expectedResults.json")

	tested := 0
	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-KEM-1024" || group.Function != "decapsulationKeyCheck" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			tested++
			want := wantGroup.test(t, test.TcID)

			_, err := newDecapsulationKeyFromExpandedACVPCheck(decodeACVPHex(t, test.DK))
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
	prompt := readACVPFile(t, "ML-KEM-encapDecap-FIPS203", "prompt.json")
	expected := readACVPFile(t, "ML-KEM-encapDecap-FIPS203", "expectedResults.json")

	tested := 0
	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-KEM-1024" || group.Function != "encapsulationKeyCheck" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			tested++
			want := wantGroup.test(t, test.TcID)

			_, err := NewEncapsulationKey(decodeACVPHex(t, test.EK))
			if got := err == nil; got != want.TestPassed {
				t.Fatalf("tcId %d: validation result = %t, want %t", test.TcID, got, want.TestPassed)
			}
		}
	}
	if tested == 0 {
		t.Fatal("no ML-KEM-1024 ACVP encapsulationKeyCheck test cases")
	}
}

type acvpFile struct {
	TestGroups []acvpGroup `json:"testGroups"`
}

type acvpGroup struct {
	TgID         int        `json:"tgId"`
	ParameterSet string     `json:"parameterSet"`
	Function     string     `json:"function"`
	Tests        []acvpTest `json:"tests"`
}

type acvpTest struct {
	TcID       int    `json:"tcId"`
	D          string `json:"d"`
	Z          string `json:"z"`
	EK         string `json:"ek"`
	DK         string `json:"dk"`
	M          string `json:"m"`
	C          string `json:"c"`
	K          string `json:"k"`
	TestPassed bool   `json:"testPassed"`
}

func readACVPFile(t *testing.T, suite, name string) acvpFile {
	t.Helper()

	path := filepath.Join("testdata", "acvp", suite, name)
	b, path := readACVPBytes(t, path)

	var f acvpFile
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

func (f acvpFile) group(t *testing.T, tgID int) acvpGroup {
	t.Helper()
	for _, group := range f.TestGroups {
		if group.TgID == tgID {
			return group
		}
	}
	t.Fatalf("missing ACVP test group %d", tgID)
	return acvpGroup{}
}

func (g acvpGroup) test(t *testing.T, tcID int) acvpTest {
	t.Helper()
	for _, test := range g.Tests {
		if test.TcID == tcID {
			return test
		}
	}
	t.Fatalf("missing ACVP test case %d", tcID)
	return acvpTest{}
}

func decodeACVPHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode ACVP hex: %v", err)
	}
	return b
}

func decodeACVPHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b := decodeACVPHex(t, s)
	if len(b) != 32 {
		t.Fatalf("decode ACVP hex length = %d, want 32", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

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

func newDecapsulationKeyFromExpandedACVP(t *testing.T, b []byte) *DecapsulationKey {
	t.Helper()

	dk, err := newDecapsulationKeyFromExpandedACVPCheck(b)
	if err != nil {
		t.Fatal(err)
	}
	return dk
}

func newDecapsulationKeyFromExpandedACVPCheck(b []byte) (*DecapsulationKey, error) {
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
