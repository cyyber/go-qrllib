package test

import (
	"path/filepath"
	"testing"
)

// ReadACVPFile reads a NIST ACVP fixture from testdata/acvp. It accepts either
// plain JSON or gzip-compressed JSON with a .gz suffix.
func ReadACVPFile[T any](t testing.TB, suite, name string) T {
	t.Helper()

	path := filepath.Join("testdata", "acvp", suite, name)
	return ReadTestDataJSON[T](t, path)
}

// ReadACVPBytes reads an ACVP fixture, falling back from path to path+".gz".
func ReadACVPBytes(t testing.TB, path string) ([]byte, string) {
	t.Helper()
	return ReadTestDataBytes(t, path)
}

// DecodeACVPHex decodes a hex string from an ACVP fixture.
func DecodeACVPHex(t testing.TB, s string) []byte {
	t.Helper()
	return DecodeHex(t, s)
}

// DecodeACVPHexLength decodes an ACVP hex string and checks its byte length.
func DecodeACVPHexLength(t testing.TB, s string, size int) []byte {
	t.Helper()
	b := DecodeACVPHex(t, s)
	if len(b) != size {
		t.Fatalf("decode ACVP hex length = %d, want %d", len(b), size)
	}
	return b
}

// DecodeACVPHex32 decodes a 32-byte ACVP hex string.
func DecodeACVPHex32(t testing.TB, s string) [32]byte {
	t.Helper()
	b := DecodeACVPHexLength(t, s, 32)
	var out [32]byte
	copy(out[:], b)
	return out
}

// FindACVPByID returns the first ACVP fixture item with the requested ID.
func FindACVPByID[T any](t testing.TB, kind string, id int, values []T, getID func(T) int) T {
	t.Helper()
	for _, value := range values {
		if getID(value) == id {
			return value
		}
	}
	var zero T
	t.Fatalf("missing ACVP %s %d", kind, id)
	return zero
}
