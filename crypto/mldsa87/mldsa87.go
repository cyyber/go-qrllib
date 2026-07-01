// Package mldsa87 implements the post-quantum ML-DSA signature scheme specified
// in FIPS 204.
package mldsa87

import (
	"crypto"
	"errors"
	"io"

	internal "github.com/theQRL/go-qrllib/crypto/internal/mldsa87"
)

const (
	// PublicKeySize is the size in bytes of an encoded ML-DSA-87 public key.
	PublicKeySize = 2592

	// SignatureSize is the size in bytes of an encoded ML-DSA-87 signature.
	SignatureSize = 4627

	// SeedSize is the size in bytes of the seed used to deterministically
	// generate an ML-DSA-87 private key.
	SeedSize = 32

	// PrivateKeySize is the size in bytes of an ML-DSA-87 private key in seed
	// form.
	PrivateKeySize = SeedSize
)

var errUnsupportedSignerOpts = errors.New("mldsa87: opts hash must be zero; use *Options for context")

// Options contains additional options for signing and verifying ML-DSA-87
// signatures.
type Options struct {
	// Context distinguishes signatures created for different purposes. It must
	// be at most 255 bytes long. The zero value uses an empty context.
	Context []byte
}

func (*Options) HashFunc() crypto.Hash { return 0 }

// PublicKey is the type of ML-DSA-87 public keys.
type PublicKey struct {
	key *internal.PublicKey
}

// NewPublicKey constructs a public key from its PublicKeySize-byte encoded
// form.
func NewPublicKey(publicKey []byte) (*PublicKey, error) {
	key, err := internal.NewPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: key}, nil
}

// Bytes returns the PublicKeySize-byte encoded form of pub.
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

// PrivateKey is the type of ML-DSA-87 private keys.
type PrivateKey struct {
	key *internal.PrivateKey
}

// NewPrivateKey returns the private key deterministically generated from seed,
// which must be a SeedSize-byte value.
func NewPrivateKey(seed []byte) (*PrivateKey, error) {
	key, err := internal.NewPrivateKey(seed)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: key}, nil
}

// Bytes returns the SeedSize-byte private key seed.
func (priv *PrivateKey) Bytes() []byte {
	return priv.key.Bytes()
}

// PublicKey returns the public key corresponding to priv.
func (priv *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{key: priv.key.PublicKey()}
}

// Public returns the [PublicKey] corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
	return priv.PublicKey()
}

// Equal reports whether priv and x have the same value.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return priv.key.Equal(xx.key)
}

// Sign signs message using priv and opts. It implements [crypto.Signer].
// If random is nil, Sign uses crypto/rand.Reader.
func (priv *PrivateKey) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return Sign(random, priv, message, opts)
}

// SignDeterministic signs message using FIPS 204 deterministic RND_BYTES.
func (priv *PrivateKey) SignDeterministic(message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return SignDeterministic(priv, message, opts)
}

// Zeroize clears sensitive key material from memory.
func (priv *PrivateKey) Zeroize() {
	if priv == nil || priv.key == nil {
		return
	}
	priv.key.Zeroize()
}

// GenerateKey generates a public/private key pair using entropy from random.
// If random is nil, GenerateKey uses crypto/rand.Reader.
func GenerateKey(random io.Reader) (*PublicKey, *PrivateKey, error) {
	key, err := internal.GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}
	priv := &PrivateKey{key: key}
	return priv.PublicKey(), priv, nil
}

// Sign signs message with privateKey and returns a signature. If random is nil,
// Sign uses crypto/rand.Reader. A deterministic reader intentionally produces
// deterministic signatures.
func Sign(random io.Reader, privateKey *PrivateKey, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx, err := contextFromOptions(opts)
	if err != nil {
		return nil, err
	}
	if privateKey == nil {
		return nil, errors.New("mldsa87: private key is nil")
	}
	return internal.Sign(random, privateKey.key, message, ctx)
}

// SignDeterministic signs message using FIPS 204 deterministic RND_BYTES.
func SignDeterministic(privateKey *PrivateKey, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx, err := contextFromOptions(opts)
	if err != nil {
		return nil, err
	}
	if privateKey == nil {
		return nil, errors.New("mldsa87: private key is nil")
	}
	return internal.SignDeterministic(privateKey.key, message, ctx)
}

// Verify reports whether sig is a valid signature of message by publicKey.
func Verify(publicKey *PublicKey, message, sig []byte, opts crypto.SignerOpts) bool {
	ctx, err := contextFromOptions(opts)
	if err != nil || publicKey == nil || publicKey.key == nil {
		return false
	}
	return internal.Verify(publicKey.key, message, sig, ctx) == nil
}

func contextFromOptions(opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, nil
	}
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errUnsupportedSignerOpts
	}
	if o, ok := opts.(*Options); ok && o != nil {
		return o.Context, nil
	}
	return nil, nil
}
