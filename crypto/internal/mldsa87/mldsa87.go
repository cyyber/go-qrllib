package mldsa87

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
)

// PrivateKey is an in-memory ML-DSA-87 private key.
type PrivateKey struct {
	seed [SEED_BYTES]uint8
	sk   [CRYPTO_SECRET_KEY_BYTES]uint8
	pub  PublicKey

	tr  [TR_BYTES]uint8
	key [SEED_BYTES]uint8
	s1  polyVecL // NTT(s1)
	s2  polyVecK // NTT(s2)
	t0  polyVecK // NTT(t0)
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
		return nil, errors.New("mldsa87: invalid seed length")
	}
	var fixedSeed [SEED_BYTES]uint8
	defer zeroBytes(fixedSeed[:])
	copy(fixedSeed[:], seed)
	return newPrivateKey(&fixedSeed)
}

func newPrivateKey(seed *[SEED_BYTES]uint8) (*PrivateKey, error) {
	var sk [CRYPTO_SECRET_KEY_BYTES]uint8
	var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
	priv := &PrivateKey{seed: *seed}
	defer zeroBytes(sk[:])

	if _, err := cryptoSignKeypair(seed, &pk, &sk, priv, &priv.pub); err != nil {
		//coverage:ignore
		//rationale: cryptoSignKeypair only fails if sha3 operations fail, which never happens
		priv.Zeroize()
		return nil, err
	}
	priv.sk = sk
	return priv, nil
}

// Bytes returns a copy of the seed form of the private key.
func (priv *PrivateKey) Bytes() []byte {
	seed := priv.seed
	return seed[:]
}

// PublicKey returns the public key corresponding to priv.
func (priv *PrivateKey) PublicKey() *PublicKey {
	return &priv.pub
}

// Equal reports whether priv and x have the same seed.
func (priv *PrivateKey) Equal(x *PrivateKey) bool {
	return subtle.ConstantTimeCompare(priv.seed[:], x.seed[:]) == 1
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
	zeroBytes(priv.tr[:])
	zeroBytes(priv.key[:])
	zeroPolyVecL(&priv.s1)
	zeroPolyVecK(&priv.s2)
	zeroPolyVecK(&priv.t0)
}

// PublicKey is an encoded ML-DSA-87 public key.
type PublicKey struct {
	raw [CRYPTO_PUBLIC_KEY_BYTES]uint8
	tr  [TR_BYTES]uint8
	mat [K]polyVecL
	t1  polyVecK // NTT(t1 * 2^D)
}

// NewPublicKey constructs a public key from its encoded form.
func NewPublicKey(publicKey []byte) (*PublicKey, error) {
	if len(publicKey) != CRYPTO_PUBLIC_KEY_BYTES {
		return nil, errors.New("mldsa87: invalid public key length")
	}
	var raw [CRYPTO_PUBLIC_KEY_BYTES]uint8
	copy(raw[:], publicKey)
	return newPublicKeyFromRaw(&raw)
}

// Bytes returns a copy of the encoded public key.
func (pub *PublicKey) Bytes() []byte {
	raw := pub.raw
	return raw[:]
}

// Equal reports whether pub and x have the same encoded public key.
func (pub *PublicKey) Equal(x *PublicKey) bool {
	return subtle.ConstantTimeCompare(pub.raw[:], x.raw[:]) == 1
}

var errPrivateKeyNil = errors.New("mldsa87: private key is nil")

// Sign signs message using ctx and the randomness from random.
//
// Signing is hedged (FIPS 204 §3.4): the per-signature RND_BYTES are drawn
// from random. If random is nil, Sign uses crypto/rand.Reader.
func Sign(random io.Reader, privateKey *PrivateKey, message, ctx []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errPrivateKeyNil
	}
	var signature [CRYPTO_BYTES]uint8
	if err := cryptoSignSignature(random, signature[:], message, ctx, privateKey, &privateKey.pub.mat); err != nil {
		return nil, err
	}
	return signature[:], nil
}

// SignDeterministic signs message using FIPS 204 deterministic RND_BYTES.
func SignDeterministic(privateKey *PrivateKey, message, ctx []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errPrivateKeyNil
	}
	var signature [CRYPTO_BYTES]uint8
	var rnd [RND_BYTES]uint8
	if err := cryptoSignSignatureWithKeyAndRnd(signature[:], message, ctx, privateKey, &privateKey.pub.mat, rnd); err != nil {
		return nil, err
	}
	return signature[:], nil
}

// Verify verifies sig over message with ctx.
func Verify(publicKey *PublicKey, message, sig, ctx []byte) error {
	if publicKey == nil {
		return errors.New("mldsa87: public key is nil")
	}
	if len(sig) != CRYPTO_BYTES {
		return errors.New("mldsa87: invalid signature size")
	}
	var signature [CRYPTO_BYTES]uint8
	copy(signature[:], sig)
	result, err := cryptoSignVerify(signature, message, ctx, publicKey)
	if err != nil {
		return err
	}
	if !result {
		return errors.New("mldsa87: invalid signature")
	}
	return nil
}
