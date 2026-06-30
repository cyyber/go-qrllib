// Package mldsa87 provides ML-DSA-87 digital signature primitives.
//
// # Signing Mode
//
// Signing is hedged by default per FIPS 204. [GenerateKey], [Sign], and
// [PrivateKey.Sign] honour the caller-supplied randomness parameter; passing
// nil uses crypto/rand.Reader. Callers that need deterministic signatures for
// tests or protocols where determinism is itself a requirement can use
// [SignDeterministic] or pass an io.Reader that returns deterministic bytes.
package mldsa87

import (
	"crypto"
	"crypto/rand"
	"errors"
	"io"

	internal "github.com/theQRL/go-qrllib/crypto/internal/mldsa87"
)

const (
	// PublicKeySize is the size in bytes of an encoded ML-DSA-87 public key.
	PublicKeySize = internal.CRYPTO_PUBLIC_KEY_BYTES

	// SignatureSize is the size in bytes of an encoded ML-DSA-87 signature.
	SignatureSize = internal.CRYPTO_BYTES

	// SeedSize is the size in bytes of the seed used to deterministically
	// generate an ML-DSA-87 private key.
	SeedSize = internal.SEED_BYTES

	// PrivateKeySize is the size in bytes of an ML-DSA-87 private key in seed
	// form.
	PrivateKeySize = SeedSize

	// SecretKeySize is the size in bytes of the expanded ML-DSA-87 secret key.
	SecretKeySize = internal.CRYPTO_SECRET_KEY_BYTES

	// Backwards-compatible constant aliases for callers that used the old
	// crypto/ml_dsa_87 package names.
	CRYPTO_PUBLIC_KEY_BYTES = PublicKeySize
	CRYPTO_SECRET_KEY_BYTES = SecretKeySize
	CRYPTO_BYTES            = SignatureSize
)

var errUnsupportedSignerOpts = errors.New("mldsa87: opts must be *Options, *SignerOpts, or nil")

// Options contains additional options for signing and verifying ML-DSA-87
// signatures.
type Options struct {
	// Context distinguishes signatures created for different purposes. It must
	// be at most 255 bytes long. The zero value uses an empty context.
	Context []byte
}

func (*Options) HashFunc() crypto.Hash { return 0 }

// SignerOpts is an alias retained for code that previously used the
// crypto/ml_dsa_87 crypto.Signer adapter.
type SignerOpts = Options

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
	if pub == nil || pub.key == nil {
		return nil
	}
	return pub.key.Bytes()
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	if pub == nil || xx == nil {
		return pub == xx
	}
	if pub.key == nil || xx.key == nil {
		return pub.key == xx.key
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
	if priv == nil || priv.key == nil {
		return nil
	}
	return priv.key.Bytes()
}

// SecretKeyBytes returns the expanded ML-DSA-87 secret key bytes.
func (priv *PrivateKey) SecretKeyBytes() [SecretKeySize]uint8 {
	if priv == nil || priv.key == nil {
		return [SecretKeySize]uint8{}
	}
	return priv.key.SecretKeyBytes()
}

// PublicKey returns the public key corresponding to priv.
func (priv *PrivateKey) PublicKey() *PublicKey {
	if priv == nil || priv.key == nil {
		return nil
	}
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
	if priv == nil || xx == nil {
		return priv == xx
	}
	if priv.key == nil || xx.key == nil {
		return priv.key == xx.key
	}
	return priv.key.Equal(xx.key)
}

// Sign signs message using priv and opts. It implements [crypto.Signer].
// If random is nil, Sign uses crypto/rand.Reader.
func (priv *PrivateKey) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return Sign(random, priv, message, opts)
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
	if random == nil {
		random = rand.Reader
	}
	var seed [SeedSize]byte
	defer clear(seed[:])
	if _, err := io.ReadFull(random, seed[:]); err != nil {
		return nil, nil, err
	}
	priv, err := NewPrivateKey(seed[:])
	if err != nil {
		return nil, nil, err
	}
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
	return internal.VerifySignature(publicKey.key, message, sig, ctx) == nil
}

func contextFromOptions(opts crypto.SignerOpts) ([]byte, error) {
	switch o := opts.(type) {
	case nil:
		return nil, nil
	case *Options:
		if o == nil {
			return nil, nil
		}
		return o.Context, nil
	default:
		return nil, errUnsupportedSignerOpts
	}
}
