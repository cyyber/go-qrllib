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
	b00, b01, b10, b11 fftPolynomial
	tree               fprTree
}

func (priv *PrivateKey) Bytes() []byte {
	k := priv.raw
	return k[:]
}

func (priv *PrivateKey) PublicKey() []byte {
	pub := priv.pub
	return pub[:]
}

type PublicKey struct {
	raw [publicKeySize]byte
	h   ringElement
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
	if l := len(seed); l != seedSize {
		return nil, errors.New("falcon-1024: invalid seed length: " + strconv.Itoa(l))
	}

	rng := sha3.NewSHAKE256()
	rng.Write(seed)

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
	var fModQ, gModQ ringElement
	for i := range fModQ {
		fModQ[i] = fieldFromSmall(f[i])
		gModQ[i] = fieldFromSmall(g[i])
	}

	fNTT := ntt(fModQ)
	hNTT := ntt(gModQ)

	// Batch-invert fNTT with Montgomery's trick
	var fMont, pMont [n]fieldElement
	for i := range fNTT {
		if fNTT[i] == 0 {
			return ringElement{}, false
		}
		fMont[i] = fieldMontgomeryMul(fNTT[i], r2)
	}
	pMont[0] = fMont[0]
	for i := 1; i < n; i++ {
		pMont[i] = fieldMontgomeryMul(pMont[i-1], fMont[i])
	}

	// pMont[n-1] = Q*R. fieldInvMontgomery returns (1/input)*R, so this yields
	// 1/Q in plain form; one more MontMul lifts it back into Montgomery form
	// for the back-substitution.
	invRunMont := fieldMontgomeryMul(fieldInvMontgomery(pMont[n-1]), r2)

	for i := n - 1; i >= 1; i-- {
		invMont := fieldMontgomeryMul(invRunMont, pMont[i-1]) // 1/fNTT[i] in Mont form
		hNTT[i] = fieldMontgomeryMul(hNTT[i], invMont)        // h/f, back in plain form
		invRunMont = fieldMontgomeryMul(invRunMont, fMont[i]) // shift to next prefix
	}
	hNTT[0] = fieldMontgomeryMul(hNTT[0], invRunMont)

	return inverseNTT(hNTT), true
}

func initPrivateKey(priv *PrivateKey, f, g, ntruF, ntruG smallPolynomial, h ringElement) (*PrivateKey, error) {
	if err := skEncode(priv.raw[:], f, g, ntruF); err != nil {
		return nil, err
	}

	if err := pkEncode(priv.pub[:], h); err != nil {
		return nil, err
	}

	expandPrivateKey(priv, f, g, ntruF, ntruG)

	return priv, nil
}

func expandPrivateKey(priv *PrivateKey, f, g, ntruF, ntruG smallPolynomial) {
	fftFromSmall(priv.b01[:], f)
	fftFromSmall(priv.b00[:], g)
	fftFromSmall(priv.b11[:], ntruF)
	fftFromSmall(priv.b10[:], ntruG)

	polyNegSlice(priv.b01[:], logN)
	polyNegSlice(priv.b11[:], logN)

	var g00, g01, g11, tmp fftPolynomial

	copy(g00[:], priv.b00[:])
	fftMulSelfAdjSlice(g00[:], logN)
	copy(tmp[:], priv.b01[:])
	fftMulSelfAdjSlice(tmp[:], logN)
	fftAdd(g00[:], tmp[:], logN)

	fftMulAdjSlice(g01[:], priv.b00[:], priv.b10[:], logN)
	fftMulAdjSlice(tmp[:], priv.b01[:], priv.b11[:], logN)
	fftAdd(g01[:], tmp[:], logN)

	copy(g11[:], priv.b10[:])
	fftMulSelfAdjSlice(g11[:], logN)
	copy(tmp[:], priv.b11[:])
	fftMulSelfAdjSlice(tmp[:], logN)
	fftAdd(g11[:], tmp[:], logN)

	var ffLDLScratch [3 * n]fpr
	ffLDLFFT(priv.tree[:], g00, g01, g11, logN, ffLDLScratch[:])
	ffLDLBinaryNormalize(priv.tree[:], logN, logN)
}

// fftFromSmall converts a small polynomial to floating-point in place at dst,
// then runs an in-place forward FFT. dst must hold n elements.
func fftFromSmall(dst []fpr, src smallPolynomial) {
	for i := range src {
		dst[i] = fpr(src[i])
	}
	fftSlice(dst, logN)
}

func NewPrivateKey(priv []byte) (*PrivateKey, error) {
	p := &PrivateKey{}
	return newPrivateKey(p, priv)
}

func newPrivateKey(priv *PrivateKey, privBytes []byte) (*PrivateKey, error) {
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

	// Batch-invert fNTT with Montgomery's trick
	var fMont, pMont [n]fieldElement
	for i := range fNTT {
		if fNTT[i] == 0 {
			return smallPolynomial{}, false
		}
		fMont[i] = fieldMontgomeryMul(fNTT[i], r2)
	}
	pMont[0] = fMont[0]
	for i := 1; i < n; i++ {
		pMont[i] = fieldMontgomeryMul(pMont[i-1], fMont[i])
	}

	invRunMont := fieldMontgomeryMul(fieldInvMontgomery(pMont[n-1]), r2)

	for i := n - 1; i >= 1; i-- {
		invMont := fieldMontgomeryMul(invRunMont, pMont[i-1]) // 1/fNTT[i] in Mont form
		gNTT[i] = fieldMontgomeryMul(gNTT[i], invMont)        // (g·F)/f, back in plain form
		invRunMont = fieldMontgomeryMul(invRunMont, fMont[i]) // shift to next prefix
	}
	gNTT[0] = fieldMontgomeryMul(gNTT[0], invRunMont)

	ntruGModQ := inverseNTT(gNTT)

	var ntruG smallPolynomial
	for i := range ntruG {
		gi := fieldCenteredMod(ntruGModQ[i])
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
	pub.h = h
	copy(pub.raw[:], pubBytes)
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
		prng := newSamplerPRNG(rng)
		s2, ok := signTreeAttempt(prng, priv, c0)
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
	fftSlice(t0[:], logN)

	copy(t1[:], t0[:])
	fftMulSlice(t1[:], priv.b01[:], logN)
	fftMulConstSlice(t1[:], -fprInverseOfQ, logN)
	fftMulSlice(t0[:], priv.b11[:], logN)
	fftMulConstSlice(t0[:], fprInverseOfQ, logN)

	sampleX, sampleY := ffSamplingFFT(prng, t0, t1, priv.tree[:], logN)

	// Reuse latticeX / latticeY as both the FFT-domain working buffers and
	// the coefficient-domain result of inverseFFTSlice. tmp is the per-half
	// scratch for the b10 / b11 products that get added in.
	var latticeX, latticeY, tmp fftPolynomial
	copy(latticeX[:], sampleX[:])
	fftMulSlice(latticeX[:], priv.b00[:], logN)
	copy(tmp[:], sampleY[:])
	fftMulSlice(tmp[:], priv.b10[:], logN)
	fftAdd(latticeX[:], tmp[:], logN)

	copy(latticeY[:], sampleX[:])
	fftMulSlice(latticeY[:], priv.b01[:], logN)
	copy(tmp[:], sampleY[:])
	fftMulSlice(tmp[:], priv.b11[:], logN)
	fftAdd(latticeY[:], tmp[:], logN)

	inverseFFTSlice(latticeX[:], logN)
	inverseFFTSlice(latticeY[:], logN)

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
	h.Write(sig.nonce[:])
	h.Write(message)

	c0 := hashToPoint(h)

	if !verifyRaw(c0, sig.s2, pub.h) {
		return errors.New("falcon-1024: invalid signature")
	}

	return nil
}

func verifyRaw(c0 ringElement, s2 smallPolynomial, h ringElement) bool {
	var t ringElement
	for i := range t {
		t[i] = fieldFromSmall(s2[i])
	}

	tNTT := ntt(t)
	tNTT = nttMul(tNTT, toNTTMonty(h))
	t = inverseNTT(tNTT)

	var s1 smallPolynomial
	for i := range s1 {
		s1[i] = fieldCenteredMod(fieldSub(c0[i], t[i]))
	}

	return signatureNormWithinBound(s1, s2)
}
