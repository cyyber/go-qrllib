package mlkem1024

import (
	"crypto/rand"
	"io"
)

type DecapsulationKey struct{}

func (dk *DecapsulationKey) Bytes() []byte {
	// TODO
	return nil
}

type EncapsulationKey struct{}

func (ek *EncapsulationKey) Bytes() []byte {
	// TODO
	return nil
}

func GenerateKey() (*DecapsulationKey, error) {
	dk := &DecapsulationKey{}
	return generateKey(dk)
}

func generateKey(dk *DecapsulationKey) (*DecapsulationKey, error) {
	var d, z [32]byte
	if _, err := io.ReadFull(rand.Reader, d[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, z[:]); err != nil {
		return nil, err
	}
	keygen(dk, &d, &z)
	return dk, nil
}

func keygen(dk *DecapsulationKey, d *[32]byte, z *[32]byte) *DecapsulationKey {
	// TODO
	return dk
}
