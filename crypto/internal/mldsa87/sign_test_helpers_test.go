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
