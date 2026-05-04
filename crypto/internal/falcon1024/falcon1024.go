package falcon1024

import (
	"crypto/sha3"
	"errors"
	"io"
	"strconv"
)

const (
	seedSize       = 48
	publicKeySize  = 1793
	privateKeySize = 2305
	signatureSize  = 1280
)

type PrivateKey struct {
	raw [privateKeySize]byte // TODO: needed?
	pub *PublicKey
	// b00, b01, b10, b11 fprPolynomial
	// tree fprTree // ffLDL tree for sign_tree
}

func (priv *PrivateKey) Bytes() []byte {
	k := make([]byte, privateKeySize)
	copy(k, priv.raw[:])
	return k
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

// TODO
// GenerateKey generates a new Falcon-1024 private key pair.
// func GenerateKey() (*PrivateKey, error) {
// 	priv := &PrivateKey{}
// 	return generateKey(priv)
// }

// func generateKey(priv *PrivateKey) (*PrivateKey, error) {
// 	// TODO
// 	// precomputePrivateKey(priv)
// 	return nil, nil
// }

const privateKeyHeader byte = 0x50 + logN

func NewPrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	priv := &PrivateKey{}
	return newPrivateKeyFromSeed(priv, seed)
}

func newPrivateKeyFromSeed(priv *PrivateKey, seed []byte) (*PrivateKey, error) {
	if l := len(seed); l != seedSize {
		return nil, errors.New("ed25519: bad seed length: " + strconv.Itoa(l))
	}

	rng := sha3.NewSHAKE256()
	rng.Write(seed)

	return keygen(priv, rng)
}

type privateKeyPolynomials struct {
	f, g  smallPolynomial
	ntruF smallPolynomial
	ntruG smallPolynomial
	h     ringElement
}

const (
	fgBits  = 5
	fgBound = 1<<(fgBits-1) - 1

	ntruFBits  = 8
	ntruFBound = 1<<(ntruFBits-1) - 1

	keygenSqNormBound = 16823
	keygenBNormBound  = 16822.4121
)

func keygen(priv *PrivateKey, rng *sha3.SHAKE) (*PrivateKey, error) {
	for {
		f := sampleSmallPolynomial(rng)
		g := sampleSmallPolynomial(rng)

		if coefficientsExceedBound(f, fgBound) ||
			coefficientsExceedBound(g, fgBound) {
			continue
		}

		if squaredNormExceedsBound(f, g, keygenSqNormBound) {
			continue
		}

		if orthogonalizedNormExceedsBound(f, g, keygenBNormBound) {
			continue
		}

		h, ok := computePublic(f, g)
		if !ok {
			continue
		}

		ntruF, ntruG, ok := solveNTRU(f, g)
		if !ok {
			continue
		}

		if coefficientsExceedBound(ntruF, ntruFBound) ||
			coefficientsExceedBound(ntruG, ntruFBound) {
			continue
		}

		return initPrivateKey(priv, f, g, ntruF, ntruG, h)
	}
}

func computePublic(f, g smallPolynomial) (ringElement, bool) {
	// TODO
	return ringElement{}, false
}

func solveNTRU(f, g smallPolynomial) (ntruF, ntruG smallPolynomial, ok bool) {
	// TODO
	return smallPolynomial{}, smallPolynomial{}, true
}

func initPrivateKey(priv *PrivateKey, f, g, ntruF, ntruG smallPolynomial, h ringElement) (*PrivateKey, error) {
	// if err := encodePrivateKey(priv.raw[:], f, g, ntruF); err != nil {
	// 	return nil, err
	// }

	// if err := encodePublicKey(priv.pub.raw[:], h); err != nil {
	// 	return nil, err
	// }
	// priv.pub.hNTTMonty = toNTTMonty(h)

	// if err := expandPrivateKey(priv, f, g, ntruF, ntruG); err != nil {
	// 	return nil, err
	// }

	// return priv, nil

	return nil, nil
}

func expandPrivateKey(priv *PrivateKey, f, g, ntruF, ntruG smallPolynomial) error {
	// TODO
	return nil
}

func precomputePrivateKey(priv *PrivateKey, seed []byte) {
	// seed -> keygen -> f,g,F,G,h
	// encode priv.raw from f,g,F
	// encode/expand pub from h
	// expand priv signing state from f,g,F,G

	/*
		priv.raw[0] = privateKeyHeader
		rng := sha3.NewSHAKE256()
		rng.Write(seed)
		rng.Read(priv.raw[encodedHeaderSize:])

		if priv.pub == nil {
			priv.pub = &PublicKey{}
		}

		priv.raw[0] = privateKeyHeader
		priv.pub.raw[0] = publicKeyHeader

		hash := sha3.NewSHAKE256()
		hash.Write(priv.raw[:])

		h, _ := hashToPoint(hash)
		polyByteEncode(priv.pub.raw[encodedHeaderSize:], h)
		priv.pub.hNTTMonty = toNTTMonty(h)
	*/
}

func NewPrivateKey(priv []byte) (*PrivateKey, error) {
	p := &PrivateKey{}
	return newPrivateKey(p, priv)
}

func newPrivateKey(priv *PrivateKey, privBytes []byte) (*PrivateKey, error) {
	// newPrivateKey does raw -> decode f,g,F -> complete G -> compute h -> initPrivateKey
	// decode f,g,F from serialized private key
	// complete G from f,g,F
	// compute h / public key
	// expand priv signing state from f,g,F,G
	// copy priv.raw

	if l := len(privBytes); l != privateKeySize {
		return nil, errors.New("falcon-1024: bad private key length: " + strconv.Itoa(l))
	}
	if privBytes[0] != privateKeyHeader {
		return nil, errors.New("falcon-1024: bad private key")
	}
	copy(priv.raw[:], privBytes)
	// TODO
	// precomputePrivateKey(priv)
	return priv, nil
}

const publicKeyHeader byte = 0x00 + logN

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

func Sign(random io.Reader, priv *PrivateKey, message []byte) ([]byte, error) {
	signature := make([]byte, signatureSize)
	return sign(random, signature, priv, message)
}

func sign(random io.Reader, signature []byte, priv *PrivateKey, message []byte) ([]byte, error) {
	var seed [seedSize]byte
	if _, err := io.ReadFull(random, seed[:]); err != nil {
		return nil, err
	}

	rng := sha3.NewSHAKE256()
	rng.Write(seed[:])

	var nonce [nonceSize]byte
	rng.Read(nonce[:])

	hashData := sha3.NewSHAKE256()
	hashData.Write(nonce[:])
	hashData.Write(message)

	c0, err := hashToPoint(hashData)
	if err != nil {
		return nil, err
	}

	s2, err := signTree(rng, priv, c0)
	if err != nil {
		return nil, err
	}

	signature[0] = signatureHeader
	copy(signature[encodedHeaderSize:signaturePrefixSize], nonce[:])

	written, err := compressedEncode(signature[signaturePrefixSize:], s2)
	if err != nil {
		return nil, err
	}
	clear(signature[signaturePrefixSize+written:]) // double check

	return signature, nil
}

func signTree(rng io.Reader, priv *PrivateKey, c0 ringElement) (smallPolynomial, error) {
	// TODO
	return smallPolynomial{}, nil
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
