package mldsa87

import (
	"testing"
)

// FuzzPrivateKeyVerify tests that Verify handles arbitrary input without panicking
func FuzzPrivateKeyVerify(f *testing.F) {
	// Add seed corpus with various sizes
	f.Add(make([]byte, 0), make([]byte, 0), make([]byte, CRYPTO_BYTES), make([]byte, CRYPTO_PUBLIC_KEY_BYTES))
	f.Add(make([]byte, 10), make([]byte, 32), make([]byte, CRYPTO_BYTES), make([]byte, CRYPTO_PUBLIC_KEY_BYTES))
	f.Add(make([]byte, 255), make([]byte, 1000), make([]byte, CRYPTO_BYTES), make([]byte, CRYPTO_PUBLIC_KEY_BYTES))

	f.Fuzz(func(t *testing.T, ctx, message, sigBytes, pkBytes []byte) {
		// Convert to fixed-size arrays, padding or truncating as needed
		var sig [CRYPTO_BYTES]uint8
		var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8

		copy(sig[:], sigBytes)
		copy(pk[:], pkBytes)

		// This should never panic, regardless of input
		_ = Verify(ctx, message, sig, &pk)
	})
}
