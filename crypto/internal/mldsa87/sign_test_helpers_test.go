package mldsa87

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

func verifyForTest(ctx, message []byte, signature [CRYPTO_BYTES]uint8, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8) bool {
	if pk == nil {
		return Verify(nil, message, signature[:], ctx) == nil
	}
	return Verify(&PublicKey{raw: *pk}, message, signature[:], ctx) == nil
}
