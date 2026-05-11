package falcon1024

import (
	"crypto/rand"
	"testing"
)

func benchSignSetup(b *testing.B) (*PrivateKey, []byte) {
	b.Helper()
	var seed [seedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		b.Fatal(err)
	}
	priv, err := NewPrivateKeyFromSeed(seed[:])
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("falcon-1024 sign benchmark message")
	return priv, msg
}

func BenchmarkSign(b *testing.B) {
	priv, msg := benchSignSetup(b)
	b.ResetTimer()
	for range b.N {
		if _, err := Sign(rand.Reader, priv, msg); err != nil {
			b.Fatal(err)
		}
	}
}
