package mldsa87

import (
	"bytes"
	"crypto/rand"
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

// PrivateKey is an in-memory ML-DSA-87 private key.
type PrivateKey struct {
	seed [SEED_BYTES]uint8
	sk   [CRYPTO_SECRET_KEY_BYTES]uint8
	pub  PublicKey
}

// GenerateKey generates a fresh ML-DSA-87 private key using entropy from random.
// If random is nil, GenerateKey uses crypto/rand.Reader.
func GenerateKey(random io.Reader) (*PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}

	var seed [SEED_BYTES]uint8
	defer zeroBytes(seed[:])
	if _, err := io.ReadFull(random, seed[:]); err != nil {
		return nil, err
	}
	return newPrivateKey(&seed)
}

// NewPrivateKey returns the private key deterministically generated from seed.
func NewPrivateKey(seed []byte) (*PrivateKey, error) {
	if len(seed) != SEED_BYTES {
		return nil, errInvalidSeedLength
	}
	var fixedSeed [SEED_BYTES]uint8
	defer zeroBytes(fixedSeed[:])
	copy(fixedSeed[:], seed)
	return newPrivateKey(&fixedSeed)
}

func newPrivateKey(seed *[SEED_BYTES]uint8) (*PrivateKey, error) {
	var sk [CRYPTO_SECRET_KEY_BYTES]uint8
	var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
	defer zeroBytes(sk[:])

	if _, err := cryptoSignKeypair(seed, &pk, &sk); err != nil {
		//coverage:ignore
		//rationale: cryptoSignKeypair only fails if sha3 operations fail, which never happens
		return nil, err
	}
	return &PrivateKey{
		seed: *seed,
		sk:   sk,
		pub:  PublicKey{key: pk},
	}, nil
}

// Bytes returns a copy of the seed form of the private key.
func (priv *PrivateKey) Bytes() []byte {
	if priv == nil {
		return nil
	}
	return bytes.Clone(priv.seed[:])
}

// PublicKey returns the public key corresponding to priv.
func (priv *PrivateKey) PublicKey() *PublicKey {
	if priv == nil {
		return nil
	}
	return &priv.pub
}

// Equal reports whether priv and x have the same seed.
func (priv *PrivateKey) Equal(x *PrivateKey) bool {
	if priv == nil || x == nil {
		return priv == x
	}
	return subtle.ConstantTimeCompare(priv.seed[:], x.seed[:]) == 1
}

// Sign the message with the given context, and return a detached signature.
// The ctx parameter is required by FIPS 204 for domain separation (max 255 bytes).
// ML-DSA-87 detached signatures are fixed-size: exactly CRYPTO_BYTES (4,627) bytes.
//
// Signing is hedged (FIPS 204 §3.4): the per-signature RND_BYTES are
// drawn from random. If random is nil, Sign uses crypto/rand.Reader, so
// two calls with the same (ctx, message) under the same key produce
// distinct signatures, both of which verify under the same public key.
// (TOB-QRLLIB-6.)
func (priv *PrivateKey) Sign(random io.Reader, ctx, message []uint8) ([CRYPTO_BYTES]uint8, error) {
	var signature [CRYPTO_BYTES]uint8
	if priv == nil {
		return signature, errPrivateKeyNil
	}
	if err := cryptoSignSignature(random, signature[:], message, ctx, &priv.sk); err != nil {
		return signature, err
	}
	return signature, nil
}

// SignDeterministic produces an ML-DSA-87 signature using the FIPS 204
// §3.5 deterministic mode (per-signature RND_BYTES = 32 zero bytes).
func (priv *PrivateKey) SignDeterministic(ctx, message []uint8) ([CRYPTO_BYTES]uint8, error) {
	var signature [CRYPTO_BYTES]uint8
	if priv == nil {
		return signature, errPrivateKeyNil
	}
	var rnd [RND_BYTES]uint8 // zero — FIPS 204 §3.5 deterministic mode
	if err := cryptoSignSignatureWithRnd(signature[:], message, ctx, &priv.sk, rnd); err != nil {
		return signature, err
	}
	return signature, nil
}

// Zeroize clears sensitive key material from memory.
//
// Zeroisation in this library is best-effort, not absolute. Go's runtime may
// have copied values before Zeroize executes; such copies are outside the
// library's control. See SECURITY.md ("Key Zeroization") for the full
// discussion.
func (priv *PrivateKey) Zeroize() {
	if priv == nil {
		return
	}
	zeroBytes(priv.sk[:])
	zeroBytes(priv.seed[:])
}

// PublicKey is an encoded ML-DSA-87 public key.
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

// Sign signs message using ctx and the randomness from random.
func Sign(random io.Reader, privateKey *PrivateKey, message, ctx []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errPrivateKeyNil
	}
	signature, err := privateKey.Sign(random, ctx, message)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(signature[:]), nil
}

// SignDeterministic signs message using FIPS 204 deterministic RND_BYTES.
func SignDeterministic(privateKey *PrivateKey, message, ctx []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errPrivateKeyNil
	}
	signature, err := privateKey.SignDeterministic(ctx, message)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(signature[:]), nil
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

// Verify checks the signature against the message and public key with the given context.
// The ctx parameter must match the context used during signing (FIPS 204 requirement).
// Returns false if pk is nil rather than panicking. (TOB-QRLLIB-11)
func Verify(ctx, message []uint8, signature [CRYPTO_BYTES]uint8, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8) bool {
	if pk == nil {
		return false
	}
	result, err := cryptoSignVerify(signature, message, ctx, pk)
	if err != nil {
		return false
	}
	return result
}
