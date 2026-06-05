package testutil

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// ReadJSON reads a JSON test fixture from path, falling back to path+".gz".
func ReadJSON[T any](t testing.TB, path string) T {
	t.Helper()

	b, path := ReadFile(t, path)
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("parse JSON %q: %v", path, err)
	}
	return out
}

// ReadFile reads a test fixture from path, falling back to path+".gz".
func ReadFile(t testing.TB, path string) ([]byte, string) {
	t.Helper()

	gzPath := path
	if !strings.HasSuffix(gzPath, ".gz") {
		if b, err := os.ReadFile(path); err == nil {
			return b, path
		}
		gzPath += ".gz"
	}

	f, err := os.Open(gzPath)
	if err != nil {
		t.Fatalf("read test fixture %q: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("open compressed test fixture %q: %v", gzPath, err)
	}
	defer func() { _ = gz.Close() }()

	b, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("read compressed test fixture %q: %v", gzPath, err)
	}
	return b, gzPath
}
