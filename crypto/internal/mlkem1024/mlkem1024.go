package mlkem1024

import (
	"crypto/rand"
	"io"
)

type DecapsulationKey struct{}

type EncapsulationKey struct{}

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

	// TODO

	return &DecapsulationKey{}, nil
}
