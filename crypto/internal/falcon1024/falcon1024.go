package falcon1024

import (
	"crypto/sha3"
	"crypto/subtle"
	"errors"
	"io"
	"strconv"
)

const (
	SeedSize              = 48
	PublicKeySize         = 1793
	encodedPrivateKeySize = 2305
	SignatureSize         = 1280
)

type PrivateKey struct {
	seed               [SeedSize]byte
	raw                [encodedPrivateKeySize]byte
	pub                *PublicKey
	b00, b01, b10, b11 fftPolynomial
	tree               fprTree
}

func (priv *PrivateKey) Equal(x *PrivateKey) bool {
	// use seed ? check mldsa stdlib
	return subtle.ConstantTimeCompare(priv.raw[:], x.raw[:]) == 1
}

func (priv *PrivateKey) Bytes() []byte {
	k := priv.seed
	return k[:]
}

func (priv *PrivateKey) encodedBytes() []byte {
	k := priv.raw
	return k[:]
}

func (priv *PrivateKey) PublicKey() *PublicKey {
	return priv.pub
}

type PublicKey struct {
	raw  [PublicKeySize]byte
	hNTT ringElement
}

func (pub *PublicKey) Equal(x *PublicKey) bool {
	return subtle.ConstantTimeCompare(pub.raw[:], x.raw[:]) == 1
}

func (pub *PublicKey) Bytes() []byte {
	pk := pub.raw
	return pk[:]
}

func NewPrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	priv := &PrivateKey{}
	return newPrivateKeyFromSeed(priv, seed)
}

func newPrivateKeyFromSeed(priv *PrivateKey, seed []byte) (*PrivateKey, error) {
	if l := len(seed); l != SeedSize {
		return nil, errors.New("falcon-1024: invalid seed length: " + strconv.Itoa(l))
	}
	copy(priv.seed[:], seed)

	rng := sha3.NewSHAKE256()
	_, _ = rng.Write(seed)

	return keygen(priv, rng)
}

const (
	fgBound           = 15
	keygenSqNormBound = 16823
	keygenBNormBound  = 16822.4121
)

func keygen(priv *PrivateKey, rng *sha3.SHAKE) (*PrivateKey, error) {
	for {
		f := sampleGaussianPolynomial(rng)
		g := sampleGaussianPolynomial(rng)

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

		ntruF, ntruG, ok := solveNTRU(f, g)
		if !ok {
			continue
		}

		h, ok := computePublic(f, g)
		if !ok {
			continue
		}

		return initPrivateKey(priv, f, g, ntruF, ntruG, h)
	}
}

func computePublic(f, g smallPolynomial) (ringElement, bool) {
	var fNTT, hNTT ringElement
	for i := range fNTT {
		fNTT[i] = fieldFromSmall(f[i])
		hNTT[i] = fieldFromSmall(g[i])
	}

	ntt(fNTT[:])
	ntt(hNTT[:])

	if !divideNTTByBatchedInverse(hNTT[:], fNTT[:]) {
		return ringElement{}, false
	}

	inverseNTT(hNTT[:])
	return hNTT, true
}

func initPrivateKey(priv *PrivateKey, f, g, ntruF, ntruG smallPolynomial, h ringElement) (*PrivateKey, error) {
	if err := skEncode(priv.raw[:], f, g, ntruF); err != nil {
		return nil, err
	}

	pub, err := newPublicKeyFromH(h)
	if err != nil {
		return nil, err
	}
	priv.pub = pub

	expandPrivateKey(priv, f, g, ntruF, ntruG)

	return priv, nil
}

func newPublicKeyFromH(h ringElement) (*PublicKey, error) {
	pub := &PublicKey{}
	if err := pkEncode(pub.raw[:], h); err != nil {
		return nil, err
	}
	pub.hNTT = h
	toNTTMonty(pub.hNTT[:])
	return pub, nil
}

func expandPrivateKey(priv *PrivateKey, f, g, ntruF, ntruG smallPolynomial) {
	fftFromSmall(priv.b01[:], f)
	fftFromSmall(priv.b00[:], g)
	fftFromSmall(priv.b11[:], ntruF)
	fftFromSmall(priv.b10[:], ntruG)

	fftNeg(priv.b01[:], logN)
	fftNeg(priv.b11[:], logN)

	var g00, g01, g11, tmp fftPolynomial

	fftSelfAdj(g00[:], priv.b00[:], logN)
	fftSelfAdj(tmp[:], priv.b01[:], logN)
	fftAdd(g00[:], tmp[:], logN)

	fftMulAdj(g01[:], priv.b00[:], priv.b10[:], logN)
	fftMulAdj(tmp[:], priv.b01[:], priv.b11[:], logN)
	fftAdd(g01[:], tmp[:], logN)

	fftSelfAdj(g11[:], priv.b10[:], logN)
	fftSelfAdj(tmp[:], priv.b11[:], logN)
	fftAdd(g11[:], tmp[:], logN)

	var ffLDLScratch [3 * n]fpr
	ffLDLFFT(priv.tree[:], g00[:], g01[:], g11[:], logN, ffLDLScratch[:])
	ffLDLBinaryNormalize(priv.tree[:], logN, logN)
}

func NewPrivateKey(seed []byte) (*PrivateKey, error) {
	return NewPrivateKeyFromSeed(seed)
}

func newPrivateKeyFromEncoded(privBytes []byte) (*PrivateKey, error) {
	p := &PrivateKey{}
	return newPrivateKeyFromEncodedInto(p, privBytes)
}

func newPrivateKeyFromEncodedInto(priv *PrivateKey, privBytes []byte) (*PrivateKey, error) {
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
	var gNTT, ntruFNTT, fNTT ringElement
	for i := range gNTT {
		gNTT[i] = fieldFromSmall(g[i])
		ntruFNTT[i] = fieldFromSmall(ntruF[i])
		fNTT[i] = fieldFromSmall(f[i])
	}

	ntt(gNTT[:])
	ntt(ntruFNTT[:])
	ntt(fNTT[:])

	for i := range gNTT {
		gNTT[i] = fieldMontgomeryMul(gNTT[i], r2)
	}
	nttMul(gNTT[:], ntruFNTT[:])

	if !divideNTTByBatchedInverse(gNTT[:], fNTT[:]) {
		return smallPolynomial{}, false
	}

	inverseNTT(gNTT[:])

	var ntruG smallPolynomial
	for i := range ntruG {
		gi := fieldCenteredMod(gNTT[i])
		if gi < -ntruCoeffBound || gi > ntruCoeffBound {
			return smallPolynomial{}, false
		}
		ntruG[i] = gi
	}

	return ntruG, true
}

func NewPublicKey(pub []byte) (*PublicKey, error) {
	p := &PublicKey{}
	return newPublicKey(p, pub)
}

func newPublicKey(pub *PublicKey, pubBytes []byte) (*PublicKey, error) {
	h, err := pkDecode(pubBytes)
	if err != nil {
		return nil, err
	}
	pub.hNTT = h
	toNTTMonty(pub.hNTT[:])
	copy(pub.raw[:], pubBytes)
	return pub, nil
}

func Sign(random io.Reader, priv *PrivateKey, message []byte) ([]byte, error) {
	signature := make([]byte, SignatureSize)
	return sign(random, signature, priv, message)
}

func sign(random io.Reader, signature []byte, priv *PrivateKey, message []byte) ([]byte, error) {
	var seed [SeedSize]byte
	if _, err := io.ReadFull(random, seed[:]); err != nil {
		return nil, err
	}

	rng := sha3.NewSHAKE256()
	_, _ = rng.Write(seed[:])

	var nonce [nonceSize]byte
	_, _ = rng.Read(nonce[:])

	hashData := sha3.NewSHAKE256()
	_, _ = hashData.Write(nonce[:])
	_, _ = hashData.Write(message)

	c0 := hashToPoint(hashData)

	for {
		s2 := signTree(rng, priv, c0)

		if err := sigEncode(signature, nonce, s2); err != nil {
			if errors.Is(err, errCompressedSignatureTooLarge) ||
				errors.Is(err, errCompressedCoefficientOutOfRange) {
				continue
			}
			return nil, err
		}

		return signature, nil
	}
}

func signTree(rng *sha3.SHAKE, priv *PrivateKey, c0 ringElement) smallPolynomial {
	for {
		var prng samplerPRNG
		initSamplerPRNG(&prng, rng)
		s2, ok := signTreeAttempt(&prng, priv, c0)
		if ok {
			return s2
		}
	}
}

func signTreeAttempt(prng *samplerPRNG, priv *PrivateKey, c0 ringElement) (smallPolynomial, bool) {
	var t0, t1 fftPolynomial
	for i := range t0 {
		t0[i] = fpr(c0[i])
	}
	fft(t0[:], logN)

	copy(t1[:], t0[:])
	fftMul(t1[:], priv.b01[:], logN)
	fftMulConst(t1[:], -fprInverseOfQ, logN)
	fftMul(t0[:], priv.b11[:], logN)
	fftMulConst(t0[:], fprInverseOfQ, logN)

	var sampleX, sampleY fftPolynomial
	ffSamplingFFT(prng, sampleX[:], sampleY[:], t0[:], t1[:], priv.tree[:], logN)

	var latticeX, latticeY, tmp fftPolynomial
	copy(latticeX[:], sampleX[:])
	fftMul(latticeX[:], priv.b00[:], logN)
	copy(tmp[:], sampleY[:])
	fftMul(tmp[:], priv.b10[:], logN)
	fftAdd(latticeX[:], tmp[:], logN)

	copy(latticeY[:], sampleX[:])
	fftMul(latticeY[:], priv.b01[:], logN)
	copy(tmp[:], sampleY[:])
	fftMul(tmp[:], priv.b11[:], logN)
	fftAdd(latticeY[:], tmp[:], logN)

	inverseFFT(latticeX[:], logN)
	inverseFFT(latticeY[:], logN)

	var s2 smallPolynomial
	var sqn uint32
	var ng uint32

	for i := range s2 {
		s1 := int32(c0[i]) - int32(fprRint(latticeX[i]))
		sqn += uint32(s1 * s1)
		ng |= sqn

		s2[i] = -int32(fprRint(latticeY[i]))
	}

	sqn |= -(ng >> 31)

	if signatureNormExceedsPartialBound(sqn, s2) {
		return smallPolynomial{}, false
	}

	return s2, true
}

const nonceSize = 40

type Signature struct {
	nonce [nonceSize]byte
	s2    smallPolynomial
}

func NewSignature(sig []byte) (*Signature, error) {
	s := &Signature{}
	return newSignature(s, sig)
}

func newSignature(sig *Signature, sigBytes []byte) (*Signature, error) {
	nonce, s2, err := sigDecode(sigBytes)
	if err != nil {
		return nil, err
	}
	sig.nonce = nonce
	sig.s2 = s2

	return sig, nil
}

func Verify(pub *PublicKey, message []byte, sig *Signature) error {
	return verify(pub, message, sig)
}

func verify(pub *PublicKey, message []byte, sig *Signature) error {
	h := sha3.NewSHAKE256()
	_, _ = h.Write(sig.nonce[:])
	_, _ = h.Write(message)

	c0 := hashToPoint(h)

	if !verifyRaw(c0, sig.s2, pub.hNTT) {
		return errors.New("falcon-1024: invalid signature")
	}

	return nil
}

func verifyRaw(c0 ringElement, s2 smallPolynomial, hNTT ringElement) bool {
	var t ringElement
	for i := range t {
		t[i] = fieldFromSmall(s2[i])
	}

	ntt(t[:])
	nttMul(t[:], hNTT[:])
	inverseNTT(t[:])

	var s1 smallPolynomial
	for i := range s1 {
		s1[i] = fieldCenteredMod(fieldSub(c0[i], t[i]))
	}

	return signatureNormWithinBound(s1, s2)
}
