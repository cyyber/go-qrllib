package falcon1024

import (
	"crypto/sha3"
	"errors"
	"strconv"
)

const (
	seedSize       = 48
	publicKeySize  = 1793
	privateKeySize = 2305
	signatureSize  = 1280
)

type PrivateKey struct {
	raw  [privateKeySize]byte
	pub  *PublicKey
	seed [seedSize]byte
	// WIP
	// b00, b01, b10, b11 fprPolynomial
	// tree fprTree // ffLDL tree for sign_tree
}

func (priv *PrivateKey) Bytes() []byte {
	k := make([]byte, privateKeySize)
	copy(k, priv.raw[:])
	return k
}

func (priv *PrivateKey) Seed() []byte {
	seed := priv.seed
	return seed[:]
}

func (priv *PrivateKey) PublicKey() *PublicKey {
	return priv.pub
}

type PublicKey struct {
	raw       [publicKeySize]byte
	hNTTMonty nttElement
}

func (pub *PublicKey) Bytes() []byte {
	k := make([]byte, publicKeySize)
	copy(k, pub.raw[:])
	return k
}

// GenerateKey generates a new Falcon-1024 private key pair.
func GenerateKey() (*PrivateKey, error) {
	priv := &PrivateKey{}
	return generateKey(priv)
}

func generateKey(priv *PrivateKey) (*PrivateKey, error) {
	precomputePrivateKey(priv)
	return nil, nil
}

func NewPrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	priv := &PrivateKey{}
	return newPrivateKeyFromSeed(priv, seed)
}

func newPrivateKeyFromSeed(priv *PrivateKey, seed []byte) (*PrivateKey, error) {
	if l := len(seed); l != seedSize {
		return nil, errors.New("ed25519: bad seed length: " + strconv.Itoa(l))
	}
	copy(priv.seed[:], seed)
	precomputePrivateKey(priv)
	return priv, nil
}

func precomputePrivateKey(priv *PrivateKey) {}

func NewPrivateKey(priv []byte) (*PrivateKey, error) {
	p := &PrivateKey{}
	return newPrivateKey(p, priv)
}

func newPrivateKey(priv *PrivateKey, privBytes []byte) (*PrivateKey, error) {
	if l := len(privBytes); l != privateKeySize {
		return nil, errors.New("falcon1024: bad private key length: " + strconv.Itoa(l))
	}
	// WIP
	/*
		if privBytes[0] != privateKeyHdr {
			return nil, errors.New("falcon1024: bad private key")
		}

		copy(priv.raw[:], privBytes)

		rawPub, err := falcontmp.PrivateKey(privBytes).Public()
		if err != nil {
			return nil, errors.New("falcon1024: bad private key")
		}

		if priv.pub == nil {
			priv.pub = &PublicKey{}
		}
		copy(priv.pub.raw[:], rawPub)
		return priv, nil
	*/
	return nil, nil
}

const (
	publicKeyHeader byte = 0x00 + logN
)

func NewPublicKey(pub []byte) (*PublicKey, error) {
	p := &PublicKey{}
	return newPublicKey(p, pub)
}

func newPublicKey(pub *PublicKey, pubBytes []byte) (*PublicKey, error) {
	if l := len(pubBytes); l != publicKeySize {
		return nil, errors.New("falcon-1024: invalid public key length")
	}
	if pubBytes[0] != publicKeyHeader {
		return nil, errors.New("falcon-1024: invalid public key")
	}

	h, err := polyByteDecode[ringElement](pubBytes[encodedHeaderSize:])
	if err != nil {
		return nil, err
	}

	copy(pub.raw[:], pubBytes)
	pub.hNTTMonty = toNTTMonty(h)
	return pub, nil
}

func Sign(priv *PrivateKey, message []byte) []byte {
	// WIP
	return nil
}

func sign(signature []byte, priv *PrivateKey, message []byte) []byte {
	// WIP
	return nil
}

func Verify(pub *PublicKey, message []byte, sig *Signature) error {
	return verify(pub, message, sig)
}

const (
	signatureHeader     byte = 0x30 + logN
	nonceSize                = 40
	encodedHeaderSize        = 1
	signaturePrefixSize      = encodedHeaderSize + nonceSize
)

type Signature struct {
	nonce [nonceSize]byte
	s2    smallPolynomial
}

func NewSignature(sig []byte) (*Signature, error) {
	s := &Signature{}
	return newSignature(s, sig)
}

func newSignature(sig *Signature, sigBytes []byte) (*Signature, error) {
	if l := len(sigBytes); l != signatureSize {
		return nil, errors.New("falcon-1024: bad signature length: " + strconv.Itoa(l))
	}
	if sigBytes[0] != signatureHeader {
		return nil, errors.New("falcon-1024: invalid signature")
	}

	copy(sig.nonce[:], sigBytes[encodedHeaderSize:signaturePrefixSize])

	s2, consumed, err := compressedDecode(sigBytes[signaturePrefixSize:])
	if err != nil {
		return nil, err
	}
	sig.s2 = s2

	for _, b := range sigBytes[signaturePrefixSize+consumed:] {
		if b != 0 {
			return nil, errors.New("falcon-1024: invalid signature")
		}
	}

	return sig, nil
}

func verify(pub *PublicKey, message []byte, sig *Signature) error {
	h := sha3.NewSHAKE256()
	h.Write(sig.nonce[:])
	h.Write(message)

	c0, err := hashToPoint(h)
	if err != nil {
		return err
	}

	if !verifyRaw(c0, sig.s2, pub.hNTTMonty) {
		return errors.New("falcon-1024: invalid signature")
	}

	return nil
}

func verifyRaw(c0 ringElement, s2 smallPolynomial, h nttElement) bool {
	var t ringElement
	for i := range t {
		t[i] = fieldFromSmall(s2[i])
	}

	tNTT := ntt(t)
	tNTT = nttMul(tNTT, h)
	t = inverseNTT(tNTT)

	var s1 smallPolynomial
	for i := range s1 {
		s1[i] = fieldCenteredMod(fieldSub(c0[i], t[i]))
	}

	return signatureNormWithinBound(s1, s2)
}
