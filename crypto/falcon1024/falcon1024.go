// Package falcon1024 implements Falcon-1024 key generation, signing, and
// verification.
//
// The package currently supports padded Falcon signatures: fixed-size
// signatures with a compressed payload and zero padding.
package falcon1024

import (
	"crypto"
	"crypto/rand"
	"io"

	"github.com/theQRL/go-qrllib/crypto/internal/falcon1024"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 1793
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 2305
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 1280
	// SeedSize is the size, in bytes, of private key seeds.
	SeedSize = 48
)

// PublicKey is the type of Falcon-1024 public keys.
type PublicKey struct{ key *falcon1024.PublicKey }

// NewPublicKey parses an encoded Falcon-1024 public key.
func NewPublicKey(publicKey []byte) (*PublicKey, error) {
	key, err := falcon1024.NewPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &PublicKey{key}, nil
}

// Bytes returns the encoded form of pub.
func (pub *PublicKey) Bytes() []byte {
	return pub.key.Bytes()
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return pub.key.Equal(xx.key)
}

// PrivateKey is the type of Falcon-1024 private keys.
type PrivateKey struct{ key *falcon1024.PrivateKey }

// NewPrivateKey parses an encoded Falcon-1024 private key.
func NewPrivateKey(privateKey []byte) (*PrivateKey, error) {
	key, err := falcon1024.NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{key}, nil
}

// Bytes returns the encoded form of priv.
func (priv *PrivateKey) Bytes() []byte {
	return priv.key.Bytes()
}

// Public returns the [PublicKey] corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &PublicKey{key: priv.key.PublicKey()}
}

// Equal reports whether priv and x have the same value.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return priv.key.Equal(xx.key)
}

// Sign signs the message with priv and returns a signature.
func (priv *PrivateKey) Sign(random io.Reader, message []byte) (signature []byte, err error) {
	return Sign(random, priv, message)
}

// GenerateKey generates a public/private key pair using entropy from random.
// If random is nil, GenerateKey uses crypto/rand.Reader.
func GenerateKey(random io.Reader) (*PublicKey, *PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, nil, err
	}

	return NewKeyFromSeed(seed)
}

// NewKeyFromSeed generates a public/private key pair from a SeedSize-byte seed.
func NewKeyFromSeed(seed []byte) (*PublicKey, *PrivateKey, error) {
	key, err := falcon1024.NewPrivateKeyFromSeed(seed)
	if err != nil {
		return nil, nil, err
	}
	return &PublicKey{key: key.PublicKey()}, &PrivateKey{key}, nil
}

// Sign signs the message with privateKey and returns a signature.
// If random is nil, Sign uses crypto/rand.Reader.
//
// It returns an error if privateKey is invalid or random fails.
func Sign(random io.Reader, privateKey *PrivateKey, message []byte) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}

	signature := make([]byte, SignatureSize)
	if err := sign(random, signature, privateKey, message); err != nil {
		return nil, err
	}
	return signature, nil
}

func sign(random io.Reader, signature []byte, privateKey *PrivateKey, message []byte) error {
	sig, err := falcon1024.Sign(random, privateKey.key, message)
	if err != nil {
		return err
	}
	copy(signature, sig)
	return nil
}

// Verify reports whether sig is a valid signature of message by publicKey.
func Verify(publicKey *PublicKey, message, sig []byte) bool {
	return verify(publicKey, message, sig) == nil
}

func verify(publicKey *PublicKey, message, sig []byte) error {
	s, err := falcon1024.NewSignature(sig)
	if err != nil {
		return err
	}
	return falcon1024.Verify(publicKey.key, message, s)
}
