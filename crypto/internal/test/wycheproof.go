package test

import (
	"os"
	"path/filepath"
	"testing"
)

// WycheproofDir returns the local Wycheproof fixture directory, unless
// WYCHEPROOF_VECTORS_DIR points at an external checkout.
func WycheproofDir() string {
	return envOrTestDataDir("WYCHEPROOF_VECTORS_DIR", "wycheproof")
}

// CCTVDir returns the local CCTV fixture directory, unless CCTV_VECTORS_DIR
// points at an external checkout.
func CCTVDir() string {
	return envOrTestDataDir("CCTV_VECTORS_DIR", "cctv")
}

func envOrTestDataDir(envName, testDataName string) string {
	if dir := os.Getenv(envName); dir != "" {
		return dir
	}
	return filepath.Join("testdata", testDataName)
}

// ReadWycheproofJSON reads a Wycheproof JSON fixture from the active vector
// directory. It accepts either plain JSON or gzip-compressed JSON with a .gz
// suffix.
func ReadWycheproofJSON[T any](t testing.TB, name string) T {
	t.Helper()
	return ReadTestDataJSON[T](t, filepath.Join(WycheproofDir(), name))
}

// HasFlag reports whether flags contains want.
func HasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}
