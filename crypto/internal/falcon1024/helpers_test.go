package falcon1024

import (
	"encoding/hex"
	"slices"
	"testing"
)

func requireEqualWords(t *testing.T, name string, got, want []uint32) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustDecodeSmallPolynomialHex(t *testing.T, s string) smallPolynomial {
	t.Helper()
	b := mustDecodeHex(t, s)
	if len(b) != n {
		t.Fatalf("decoded polynomial length = %d, want %d", len(b), n)
	}
	var p smallPolynomial
	for i, v := range b {
		p[i] = int32(int8(v))
	}
	return p
}
