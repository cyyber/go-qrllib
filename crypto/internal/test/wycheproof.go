package test

import (
	"path/filepath"
	"testing"
)

// WycheproofDir returns the local Wycheproof fixture directory.
func WycheproofDir() string {
	return filepath.Join("testdata", "wycheproof")
}

// CCTVDir returns the local CCTV fixture directory.
func CCTVDir() string {
	return filepath.Join("testdata", "cctv")
}

// ReadWycheproofJSON reads a Wycheproof JSON fixture from the local vector
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
