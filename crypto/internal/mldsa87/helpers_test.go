package mldsa87

import (
	"encoding/hex"
	"testing"
)

// zeroReader is an io.Reader that always returns zero bytes. It exercises
// caller-supplied entropy paths without pulling from the OS entropy source.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

type fixedByteReader byte

func (r fixedByteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

// errReader is an io.Reader that always returns a fixed error before producing
// any bytes.
type errReader struct{ err error }

func (e errReader) Read(_ []byte) (int, error) { return 0, e.err }

func newPrivateKeyFromSeed(t *testing.T, hexSeed string) *PrivateKey {
	t.Helper()

	binUnsizeSeed, err := hex.DecodeString(hexSeed)
	if err != nil {
		t.Fatal("failed to decode hexseed", err.Error())
	}

	var binSeed [SEED_BYTES]uint8
	copy(binSeed[:], binUnsizeSeed)

	d, err := NewPrivateKey(binSeed[:])
	if err != nil {
		t.Fatal("failed to generate new ml-dsa-87 from seed", err.Error())
	}
	if d == nil {
		t.Fatal("ml-dsa-87 is nil")
	}

	return d
}

func verifyForTest(ctx, message, signature []byte, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8) bool {
	if pk == nil {
		return Verify(nil, message, signature, ctx) == nil
	}
	pub, err := newPublicKeyFromRaw(pk)
	if err != nil {
		return false
	}
	return Verify(pub, message, signature, ctx) == nil
}
