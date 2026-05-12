// Package falcon1024 implements Falcon-1024 key generation, signing, and verification.
package falcon1024

import (
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"

	"github.com/theQRL/go-qrllib/crypto/internal/cache"
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
type PublicKey []byte

// Equal reports whether pub and x have the same value.
func (pub PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(PublicKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(pub, xx) == 1
}

// PrivateKey is the type of Falcon-1024 private keys.
type PrivateKey []byte

// Public returns the [PublicKey] corresponding to priv, or an error if priv is
// invalid.
func (priv PrivateKey) Public() (crypto.PublicKey, error) {
	k, err := cachedPrivateKey(priv)
	if err != nil {
		return nil, err
	}

	pub := make(PublicKey, PublicKeySize)
	copy(pub, k.PublicKey())
	return pub, nil
}

// Equal reports whether priv and x have the same value.
func (priv PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(PrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(priv, xx) == 1
}

// privateKeyCache uses a pointer to the first byte of underlying storage as a
// key, because [PrivateKey] is a slice header passed around by value.
var privateKeyCache cache.Cache[byte, falcon1024.PrivateKey]

func cachedPrivateKey(privateKey PrivateKey) (*falcon1024.PrivateKey, error) {
	if len(privateKey) != PrivateKeySize {
		return nil, errors.New("falcon-1024: invalid private key length")
	}

	return privateKeyCache.Get(&privateKey[0], func() (*falcon1024.PrivateKey, error) {
		return falcon1024.NewPrivateKey(privateKey)
	}, func(k *falcon1024.PrivateKey) bool {
		return subtle.ConstantTimeCompare(privateKey, k.Bytes()) == 1
	})
}

// Sign signs the message with priv and returns a signature.
func (priv PrivateKey) Sign(random io.Reader, message []byte) (signature []byte, err error) {
	return Sign(random, priv, message)
}

// GenerateKey generates a public/private key pair using entropy from random.
// If random is nil, GenerateKey uses crypto/rand.Reader.
func GenerateKey(random io.Reader) (PublicKey, PrivateKey, error) {
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
func NewKeyFromSeed(seed []byte) (PublicKey, PrivateKey, error) {
	privateKey := make([]byte, PrivateKeySize)
	publicKey := make([]byte, PublicKeySize)
	if err := newKeyFromSeed(publicKey, privateKey, seed); err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

func newKeyFromSeed(publicKey, privateKey, seed []byte) error {
	k, err := falcon1024.NewPrivateKeyFromSeed(seed)
	if err != nil {
		return err
	}
	copy(publicKey, k.PublicKey())
	copy(privateKey, k.Bytes())
	return nil
}

// Sign signs the message with privateKey and returns a signature.
// If random is nil, Sign uses crypto/rand.Reader.
//
// It returns an error if privateKey is invalid or random fails.
func Sign(random io.Reader, privateKey PrivateKey, message []byte) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	signature := make([]byte, SignatureSize)
	if err := sign(random, signature, privateKey, message); err != nil {
		return nil, err
	}
	return signature, nil
}

func sign(random io.Reader, signature []byte, privateKey PrivateKey, message []byte) error {
	k, err := cachedPrivateKey(privateKey)
	if err != nil {
		return err
	}
	sig, err := falcon1024.Sign(random, k, message)
	if err != nil {
		return err
	}
	copy(signature, sig)
	return nil
}

// Verify reports whether sig is a valid signature of message by publicKey.
func Verify(publicKey PublicKey, message, sig []byte) bool {
	return verify(publicKey, message, sig) == nil
}

func verify(publicKey PublicKey, message, sig []byte) error {
	k, err := falcon1024.NewPublicKey(publicKey)
	if err != nil {
		return err
	}

	s, err := falcon1024.NewSignature(sig)
	if err != nil {
		return err
	}

	return falcon1024.Verify(k, message, s)
}
