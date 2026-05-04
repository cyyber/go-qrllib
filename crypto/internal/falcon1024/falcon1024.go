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
	raw                [privateKeySize]byte
	pub                [publicKeySize]byte
	b00, b01, b10, b11 fprPolynomial
	tree               fprTree
}

func (priv *PrivateKey) Bytes() []byte {
	k := make([]byte, privateKeySize)
	copy(k, priv.raw[:])
	return k
}

func (priv *PrivateKey) PublicKey() []byte {
	pub := priv.pub
	return pub[:]
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
	var fModQ ringElement
	var gModQ ringElement

	for i := range fModQ {
		fModQ[i] = fieldFromSmall(f[i])
		gModQ[i] = fieldFromSmall(g[i])
	}

	fNTT := ntt(fModQ)
	hNTT := ntt(gModQ)

	for i := range hNTT {
		if fNTT[i] == 0 {
			return ringElement{}, false
		}
		hNTT[i] = fieldDiv(hNTT[i], fNTT[i])
	}

	return inverseNTT(hNTT), true
}

func initPrivateKey(priv *PrivateKey, f, g, ntruF, ntruG smallPolynomial, h ringElement) (*PrivateKey, error) {
	if err := skEncode(priv.raw[:], f, g, ntruF); err != nil {
		return nil, err
	}

	if err := pkEncode(priv.pub[:], h); err != nil {
		return nil, err
	}

	if err := expandPrivateKey(priv, f, g, ntruF, ntruG); err != nil {
		return nil, err
	}

	return nil, nil
}

func expandPrivateKey(priv *PrivateKey, f, g, ntruF, ntruG smallPolynomial) error {
	// WIP
	return nil
}

func NewPrivateKey(priv []byte) (*PrivateKey, error) {
	p := &PrivateKey{}
	return newPrivateKey(p, priv)
}

func newPrivateKey(priv *PrivateKey, privBytes []byte) (*PrivateKey, error) {
	if l := len(privBytes); l != privateKeySize {
		return nil, errors.New("falcon-1024: bad private key length: " + strconv.Itoa(l))
	}
	if privBytes[0] != privateKeyHeader {
		return nil, errors.New("falcon-1024: invalid private key")
	}

	f, g, ntruF, err := skDecode(privBytes)
	if err != nil {
		return nil, err
	}

	ntruG, ok := completePrivate(f, g, ntruF)
	if !ok {
		return nil, errors.New("falcon-1024: invalid private key")
	}

	h, ok := computePublic(f, g)
	if !ok {
		return nil, errors.New("falcon-1024: invalid private key")
	}

	return initPrivateKey(priv, f, g, ntruF, ntruG, h)
}

func completePrivate(f, g, ntruF smallPolynomial) (smallPolynomial, bool) {
	var gModQ ringElement
	var ntruFModQ ringElement

	for i := range gModQ {
		gModQ[i] = fieldFromSmall(g[i])
		ntruFModQ[i] = fieldFromSmall(ntruF[i])
	}

	gNTT := ntt(gModQ)
	ntruFNTT := ntt(ntruFModQ)

	for i := range gNTT {
		gNTT[i] = fieldMontgomeryMul(gNTT[i], r2)
	}
	gNTT = nttMul(gNTT, ntruFNTT)

	var fModQ ringElement
	for i := range fModQ {
		fModQ[i] = fieldFromSmall(f[i])
	}

	fNTT := ntt(fModQ)

	for i := range gNTT {
		if fNTT[i] == 0 {
			return smallPolynomial{}, false
		}
		gNTT[i] = fieldDiv(gNTT[i], fNTT[i])
	}

	ntruGModQ := inverseNTT(gNTT)

	var ntruG smallPolynomial
	for i := range ntruG {
		gi := fieldCenteredMod(ntruGModQ[i])
		if gi < -ntruFBound || gi > ntruFBound {
			return smallPolynomial{}, false
		}
		ntruG[i] = gi
	}

	return ntruG, true
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

	h, err := pkDecode(pubBytes)
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

	if err := sigEncode(signature, &nonce, s2); err != nil {
		return nil, err
	}

	return signature, nil
}

func signTree(rng io.Reader, priv *PrivateKey, c0 ringElement) (smallPolynomial, error) {
	// WIP
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

	nonce, s2, err := sigDecode(sigBytes)
	if err != nil {
		return nil, err
	}
	sig.nonce = nonce
	sig.s2 = s2

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
