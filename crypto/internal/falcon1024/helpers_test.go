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
