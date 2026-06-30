package mldsa87

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"io"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

var (
	errInvalidSeedLength      = errors.New("mldsa87: invalid seed length")
	errInvalidPublicKeyLength = errors.New("mldsa87: invalid public key length")
	errPrivateKeyNil          = errors.New("mldsa87: private key is nil")
	errPublicKeyNil           = errors.New("mldsa87: public key is nil")
)

// PublicKey is an encoded ML-DSA-87 public key with helper methods for the
// public facade.
type PublicKey struct {
	key [CRYPTO_PUBLIC_KEY_BYTES]uint8
}

// NewPublicKey constructs a public key from its encoded form.
func NewPublicKey(publicKey []byte) (*PublicKey, error) {
	if len(publicKey) != CRYPTO_PUBLIC_KEY_BYTES {
		return nil, errInvalidPublicKeyLength
	}
	pub := &PublicKey{}
	copy(pub.key[:], publicKey)
	return pub, nil
}

// Bytes returns a copy of the encoded public key.
func (pub *PublicKey) Bytes() []byte {
	if pub == nil {
		return nil
	}
	return bytes.Clone(pub.key[:])
}

// Equal reports whether pub and x have the same encoded public key.
func (pub *PublicKey) Equal(x *PublicKey) bool {
	if pub == nil || x == nil {
		return pub == x
	}
	return subtle.ConstantTimeCompare(pub.key[:], x.key[:]) == 1
}

// Raw returns the fixed-size encoded public key.
func (pub *PublicKey) Raw() [CRYPTO_PUBLIC_KEY_BYTES]uint8 {
	if pub == nil {
		return [CRYPTO_PUBLIC_KEY_BYTES]uint8{}
	}
	return pub.key
}

// PrivateKey is an ML-DSA-87 private key backed by the existing implementation.
type PrivateKey struct {
	key *MLDSA87
}

// NewPrivateKey returns the private key deterministically generated from seed.
func NewPrivateKey(seed []byte) (*PrivateKey, error) {
	if len(seed) != SEED_BYTES {
		return nil, errInvalidSeedLength
	}
	var fixedSeed [SEED_BYTES]uint8
	defer zeroBytes(fixedSeed[:])
	copy(fixedSeed[:], seed)
	key, err := NewMLDSA87FromSeed(fixedSeed)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: key}, nil
}

// Bytes returns a copy of the seed form of the private key.
func (priv *PrivateKey) Bytes() []byte {
	if priv == nil || priv.key == nil {
		return nil
	}
	seed := priv.key.GetSeed()
	return bytes.Clone(seed[:])
}

// SecretKeyBytes returns the expanded ML-DSA-87 secret key bytes.
func (priv *PrivateKey) SecretKeyBytes() [CRYPTO_SECRET_KEY_BYTES]uint8 {
	if priv == nil || priv.key == nil {
		return [CRYPTO_SECRET_KEY_BYTES]uint8{}
	}
	return priv.key.GetSK()
}

// PublicKey returns the public key corresponding to priv.
func (priv *PrivateKey) PublicKey() *PublicKey {
	if priv == nil || priv.key == nil {
		return nil
	}
	return &PublicKey{key: priv.key.GetPK()}
}

// Equal reports whether priv and x have the same seed.
func (priv *PrivateKey) Equal(x *PrivateKey) bool {
	if priv == nil || x == nil || priv.key == nil || x.key == nil {
		return priv == x
	}
	a := priv.key.GetSeed()
	b := x.key.GetSeed()
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// Sign signs message using ctx and the randomness from random.
func Sign(random io.Reader, privateKey *PrivateKey, message, ctx []byte) ([]byte, error) {
	if privateKey == nil || privateKey.key == nil {
		return nil, errPrivateKeyNil
	}
	signature, err := privateKey.key.Sign(random, ctx, message)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(signature[:]), nil
}

// SignDeterministic signs message using FIPS 204 deterministic RND_BYTES.
func SignDeterministic(privateKey *PrivateKey, message, ctx []byte) ([]byte, error) {
	if privateKey == nil || privateKey.key == nil {
		return nil, errPrivateKeyNil
	}
	signature, err := privateKey.key.SignDeterministic(ctx, message)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(signature[:]), nil
}

// SignAttached signs message and returns signature || message.
func SignAttached(random io.Reader, privateKey *PrivateKey, message, ctx []byte) ([]byte, error) {
	if privateKey == nil || privateKey.key == nil {
		return nil, errPrivateKeyNil
	}
	return privateKey.key.SignAttached(random, ctx, message)
}

// VerifySignature verifies sig over message with ctx.
func VerifySignature(publicKey *PublicKey, message, sig, ctx []byte) error {
	if publicKey == nil {
		return errPublicKeyNil
	}
	if len(sig) != CRYPTO_BYTES {
		return cryptoerrors.ErrInvalidSignatureSize
	}
	var signature [CRYPTO_BYTES]uint8
	copy(signature[:], sig)
	if !Verify(ctx, message, signature, &publicKey.key) {
		return cryptoerrors.ErrInvalidSignature
	}
	return nil
}

// OpenAttached verifies signatureMessage and returns the attached message.
func OpenAttached(publicKey *PublicKey, signatureMessage, ctx []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, errPublicKeyNil
	}
	return Open(ctx, signatureMessage, &publicKey.key)
}

// Zeroize clears sensitive key material from memory.
func (priv *PrivateKey) Zeroize() {
	if priv == nil || priv.key == nil {
		return
	}
	priv.key.Zeroize()
}
