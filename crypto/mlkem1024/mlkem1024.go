// Package mlkem1024 provides ML-KEM-1024 key encapsulation primitives.
package mlkem1024

import "github.com/theQRL/go-qrllib/crypto/internal/mlkem1024"

const (
	// SeedSize is the size in bytes of the seed used to deterministically generate
	// an ML-KEM-1024 decapsulation key.
	SeedSize = 64

	// SharedKeySize is the size in bytes of an ML-KEM-1024 shared secret.
	SharedKeySize = 32

	// CiphertextSize is the size in bytes of an ML-KEM-1024 ciphertext.
	CiphertextSize = 1568

	// EncapsulationKeySize is the size in bytes of an encoded ML-KEM-1024
	// encapsulation key.
	EncapsulationKeySize = 1568
)

// DecapsulationKey is an ML-KEM-1024 private key used to decapsulate
// ciphertexts and recover shared secrets.
type DecapsulationKey struct {
	key *mlkem1024.DecapsulationKey
}

// Decapsulate recovers the shared secret from an ML-KEM-1024 ciphertext using
// the decapsulation key.
func (dk *DecapsulationKey) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	return dk.key.Decapsulate(ciphertext)
}

// EncapsulationKey returns the public encapsulation key corresponding to dk.
func (dk *DecapsulationKey) EncapsulationKey() *EncapsulationKey {
	return &EncapsulationKey{dk.key.EncapsulationKey()}
}

// Bytes returns the encoded form of the decapsulation key.
func (dk *DecapsulationKey) Bytes() []byte {
	return dk.key.Bytes()
}

// EncapsulationKey is an ML-KEM-1024 public key used to encapsulate shared
// secrets for the corresponding decapsulation key.
type EncapsulationKey struct {
	key *mlkem1024.EncapsulationKey
}

// Encapsulate produces a shared secret and ciphertext pair using this
// encapsulation key.
func (ek *EncapsulationKey) Encapsulate() (sharedKey, ciphertext []byte, err error) {
	return ek.key.Encapsulate()
}

// Bytes returns the encoded form of the encapsulation key.
func (ek *EncapsulationKey) Bytes() []byte {
	return ek.key.Bytes()
}

// GenerateKey generates a new ML-KEM-1024 decapsulation key.
func GenerateKey() (*DecapsulationKey, error) {
	key, err := mlkem1024.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey{key}, nil
}
