package falcon

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/sha3"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 1793
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 2305
	// PaddedSignatureSize is the size, in bytes, of padded signatures generated and verified by this package.
	PaddedSignatureSize = 1280
	// SeedSize is the size, in bytes, of private key seeds.
	SeedSize = 48

	privateKeyHeader      byte = 0x50 + logPolyDegree
	publicKeyHeader       byte = 0x00 + logPolyDegree
	signaturePaddedHeader byte = 0x30 + logPolyDegree

	nonceSize           = 40
	encodedHeaderSize   = 1
	signaturePrefixSize = encodedHeaderSize + nonceSize

	privateKeySmallCoeffBits = 5
	privateKeyNtruFBits      = 8
)

var (
	ErrInvalidSeedSize         = errors.New("invalid seed size")
	ErrInvalidPrivateKeyFormat = errors.New("invalid private key format")
	ErrInvalidSignatureFormat  = errors.New("invalid signature format")
	ErrInvalidPublicKeyFormat  = errors.New("invalid public key format")
)

type PublicKey [PublicKeySize]byte

type PaddedSignature [PaddedSignatureSize]byte

type PrivateKey [PrivateKeySize]byte

func (priv PrivateKey) Public() (PublicKey, error) {
	return makePublic(priv)
}

func (priv PrivateKey) Sign(random io.Reader, msg []byte) (PaddedSignature, error) {
	return Sign(random, priv, msg)
}

type Seed [SeedSize]byte

func NewSeed(random io.Reader) (Seed, error) {
	if random == nil {
		random = rand.Reader
	}

	var seed Seed
	if _, err := io.ReadFull(random, seed[:]); err != nil {
		return Seed{}, err
	}

	return seed, nil
}

func SeedFromBytes(src []byte) (Seed, error) {
	if len(src) != SeedSize {
		return Seed{}, ErrInvalidSeedSize
	}
	var seed Seed
	copy(seed[:], src)
	return seed, nil
}

// GenerateKey generates a public/private key pair using entropy from random.
func GenerateKey(random io.Reader) (PrivateKey, PublicKey, error) {
	seed, err := NewSeed(random)
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	privateKey, publicKey, err := NewKeyFromSeed(seed)
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	return privateKey, publicKey, nil
}

// NewKeyFromSeed calculates a public/private key pair from a seed.
func NewKeyFromSeed(seed Seed) (PrivateKey, PublicKey, error) {
	privateKey := PrivateKey{}
	publicKey := PublicKey{}

	err := newKeyFromSeed(privateKey[:], publicKey[:], seed[:])
	if err != nil {
		return PrivateKey{}, PublicKey{}, nil
	}

	return privateKey, publicKey, nil
}

func newKeyFromSeed(priv, pub, seed []byte) error {
	rng := sha3.NewShake256()
	if _, err := rng.Write(seed[:]); err != nil {
		return err
	}

	f, g, ntruF, h, err := keygen(rng)
	if err != nil {
		return err
	}

	sk := make([]byte, PrivateKeySize)
	if err := encodePrivateKey(sk, f, g, ntruF); err != nil {
		return err
	}

	pk := make([]byte, PublicKeySize)
	if err := encodePublicKey(pk, h); err != nil {
		return err
	}

	copy(priv, sk)
	copy(pub, pk)

	return nil
}

func Sign(random io.Reader, priv PrivateKey, msg []byte) (PaddedSignature, error) {
	nonce, hashData, err := signStart(random)
	if err != nil {
		return PaddedSignature{}, nil
	}

	_, err = hashData.Write(msg)
	if err != nil {
		return PaddedSignature{}, nil
	}

	sig, err := signFinish(priv, hashData, nonce)
	if err != nil {
		return PaddedSignature{}, nil
	}

	return PaddedSignature(sig), nil
}

func signStart(random io.Reader) ([]byte, sha3.ShakeHash, error) {
	if random == nil {
		random = rand.Reader
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return nil, nil, err
	}

	hashData := sha3.NewShake256()
	if _, err := hashData.Write(nonce[:]); err != nil {
		return nil, nil, err
	}

	return nonce, hashData, nil
}

func signFinish(priv PrivateKey, hashData sha3.ShakeHash, nonce []byte) (PaddedSignature, error) {
	if priv[0] != privateKeyHeader {
		return PaddedSignature{}, ErrInvalidPrivateKeyFormat
	}

	f, g, ntruF, err := decodePrivateKey(priv[:])
	if err != nil {
		return PaddedSignature{}, err
	}

	ntruG, err := completePrivate(f, g, ntruF)
	if err != nil {
		return PaddedSignature{}, err
	}

	hm, err := hashToPointVartime(hashData)
	if err != nil {
		return PaddedSignature{}, err
	}

	sigp, err := signDyn(f, g, ntruF, ntruG, hm)
	if err != nil {
		return PaddedSignature{}, err
	}

	sig := PaddedSignature{signaturePaddedHeader}
	copy(sig[encodedHeaderSize:signaturePrefixSize], nonce[:])

	_, err = compEncode(sig[signaturePrefixSize:], sigp)
	if err != nil {
		// TODO: original code is inside loop, double check
		return PaddedSignature{}, err
	}

	return sig, nil
}

func Verify(pub PublicKey, msg, sig []byte) (bool, error) {
	if pub[0] != publicKeyHeader {
		return false, ErrInvalidPublicKeyFormat
	}

	if sig[0] != signaturePaddedHeader {
		return false, ErrInvalidSignatureFormat
	}

	hashData := sha3.NewShake256()
	if _, err := hashData.Write(sig[encodedHeaderSize:signaturePrefixSize]); err != nil {
		return false, err
	}
	if _, err := hashData.Write(msg); err != nil {
		return false, err
	}

	h, err := decodePublicKey(pub[:])
	if err != nil {
		return false, err
	}

	sigp, err := decodeSignature(sig)
	if err != nil {
		return false, err
	}

	hm, err := hashToPointVartime(hashData)
	if err != nil {
		return false, err
	}

	mqNTT(h)
	mqPolyToMonty(h)

	return verifyRaw(hm, sigp, h), nil
}

func makePublic(priv PrivateKey) (PublicKey, error) {
	// TODO: maybe re use some parts of decode private key
	offset := encodedHeaderSize

	f, written, err := trimI8Decode(priv[offset:], privateKeySmallCoeffBits)
	if err != nil {
		return PublicKey{}, err
	}
	offset += written

	g, _, err := trimI8Decode(priv[offset:], privateKeySmallCoeffBits)
	if err != nil {
		return PublicKey{}, err
	}

	h, err := computePublic(f, g)
	if err != nil {
		return PublicKey{}, err
	}

	pub := make([]byte, PublicKeySize)
	if err := encodePublicKey(pub, h); err != nil {
		return PublicKey{}, err
	}

	return PublicKey(pub), nil
}

// encodePrivateKey serializes Falcon-1024 private key fields f, g, and F.
func encodePrivateKey(dst []byte, f, g, ntruF coeffPoly) error {
	priv := PrivateKey{privateKeyHeader}
	offset := encodedHeaderSize

	written, err := trimI8Encode(priv[offset:], f, privateKeySmallCoeffBits)
	if err != nil {
		return err
	}
	offset += written

	written, err = trimI8Encode(priv[offset:], g, privateKeySmallCoeffBits)
	if err != nil {
		return err
	}
	offset += written

	written, err = trimI8Encode(priv[offset:], ntruF, privateKeyNtruFBits)
	if err != nil {
		return err
	}
	offset += written

	// TODO
	// if offset != PrivateKeySize {
	// 	return PrivateKey{}, ErrEncodePrivateKeyWrongSize
	// }

	return nil
}

func decodePrivateKey(priv []byte) (coeffPoly, coeffPoly, coeffPoly, error) {
	return coeffPoly{}, coeffPoly{}, coeffPoly{}, nil
}

// encodePublicKey serializes the Falcon-1024 public polynomial h.
func encodePublicKey(dst []byte, h mqPoly) error {
	return nil
}

func decodePublicKey(pub []byte) (mqPoly, error) {
	return mqPoly{}, nil
}

func decodeSignature(sig []byte) (coeffPoly, error) {
	return coeffPoly{}, nil
}
