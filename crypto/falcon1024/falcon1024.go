package falcon1024

import (
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"io"
	"strconv"

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

// PrivateKey is the type of Falcon-1024 private keys. It implements [crypto.Signer].
type PrivateKey []byte

// Public returns the [PublicKey] corresponding to priv.
func (priv PrivateKey) Public() (crypto.PublicKey, error) {
	k, err := privateKeyCache.Get(&priv[0], func() (*falcon1024.PrivateKey, error) {
		return falcon1024.NewPrivateKey(priv)
	}, func(k *falcon1024.PrivateKey) bool {
		return subtle.ConstantTimeCompare(priv, k.Bytes()) == 1
	})
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

func (priv PrivateKey) Sign(rand io.Reader, message []byte) (signature []byte, err error) {
	k, err := privateKeyCache.Get(&priv[0], func() (*falcon1024.PrivateKey, error) {
		return falcon1024.NewPrivateKey(priv)
	}, func(k *falcon1024.PrivateKey) bool {
		return subtle.ConstantTimeCompare(priv, k.Bytes()) == 1
	})
	if err != nil {
		return nil, err
	}

	return falcon1024.Sign(rand, k, message)
}

// GenerateKey generates a public/private key pair using entropy from random.
func GenerateKey(random io.Reader) (PublicKey, PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, nil, err
	}

	publicKey, privateKey := NewKeyFromSeed(seed)
	return publicKey, privateKey, nil
}

// NewKeyFromSeed generates a public/private key pair from a seed. It will panic if
// len(seed) is not [SeedSize].
func NewKeyFromSeed(seed []byte) (PublicKey, PrivateKey) {
	privateKey := make([]byte, PrivateKeySize)
	publicKey := make([]byte, PublicKeySize)
	newKeyFromSeed(publicKey, privateKey, seed)
	return publicKey, privateKey
}

func newKeyFromSeed(publicKey, privateKey, seed []byte) {
	k, err := falcon1024.NewPrivateKeyFromSeed(seed)
	if err != nil {
		panic("falcon-1024: bad seed length: " + strconv.Itoa(len(seed)))
	}
	copy(publicKey, k.PublicKey())
	copy(privateKey, k.Bytes())
}

// Sign signs the message with privateKey and returns a signature. It will
// panic if len(privateKey) is not [PrivateKeySize].
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
	k, err := privateKeyCache.Get(&privateKey[0], func() (*falcon1024.PrivateKey, error) {
		return falcon1024.NewPrivateKey(privateKey)
	}, func(k *falcon1024.PrivateKey) bool {
		return subtle.ConstantTimeCompare(privateKey, k.Bytes()) == 1
	})
	if err != nil {
		panic("falcon-1024: bad private key: " + err.Error())
	}
	sig, err := falcon1024.Sign(random, k, message)
	if err != nil {
		return err
	}
	copy(signature, sig)
	return nil
}

// Verify reports whether sig is a valid signature of message by publicKey. It
// will panic if len(publicKey) is not [PublicKeySize].
func Verify(publicKey PublicKey, message, sig []byte) bool {
	return verify(publicKey, message, sig) == nil
}

func verify(publicKey PublicKey, message, sig []byte) error {
	if l := len(publicKey); l != PublicKeySize {
		panic("falcon-1024: bad public key length: " + strconv.Itoa(l))
	}

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
