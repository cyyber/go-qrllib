package test

import (
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
)

// ReadTestDataJSON reads a JSON fixture from path. It accepts either plain JSON
// or gzip-compressed JSON with a .gz suffix.
func ReadTestDataJSON[T any](t testing.TB, path string) T {
	t.Helper()

	b, path := ReadTestDataBytes(t, path)
	var f T
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse test JSON %q: %v", path, err)
	}
	return f
}

// ReadTestDataBytes reads a test fixture, falling back from path to path+".gz".
func ReadTestDataBytes(t testing.TB, path string) ([]byte, string) {
	t.Helper()

	b, err := os.ReadFile(path)
	if err == nil {
		return b, path
	}

	gzPath := path + ".gz"
	f, err := os.Open(gzPath)
	if err != nil {
		t.Fatalf("read test data %q: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("open compressed test data %q: %v", gzPath, err)
	}
	defer func() { _ = gz.Close() }()

	b, err = io.ReadAll(gz)
	if err != nil {
		t.Fatalf("read compressed test data %q: %v", gzPath, err)
	}
	return b, gzPath
}

// DecodeHex decodes a hex string from a test fixture.
func DecodeHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}
