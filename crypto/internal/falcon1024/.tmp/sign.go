package falcon_1024

import "golang.org/x/crypto/sha3"

var gaussian0Dist = [...]uint32{
	10745844, 3068844, 3741698,
	5559083, 1580863, 8248194,
	2260429, 13669192, 2736639,
	708981, 4421575, 10046180,
	169348, 7122675, 4136815,
	30538, 13063405, 7650655,
	4132, 14505003, 7826148,
	417, 16768101, 11363290,
	31, 8444042, 8086568,
	1, 12844466, 265321,
	0, 1232676, 13644283,
	0, 38047, 9111839,
	0, 870, 6138264,
	0, 14, 12545723,
	0, 0, 3104126,
	0, 0, 28824,
	0, 0, 198,
	0, 0, 1,
}

func smallIntsToFPR(dst fprPoly, src coeffPoly) {
	for i := range polyDegree {
		dst[i] = fprOf(src[i])
	}
}

func gaussian0Sampler(prng *samplerPRNG) (int32, error) {
	lo, err := prng.readUint64()
	if err != nil {
		return 0, err
	}

	hiByte, err := prng.readByte()
	if err != nil {
		return 0, err
	}

	v0 := uint32(lo) & 0xFFFFFF
	v1 := uint32(lo>>24) & 0xFFFFFF
	v2 := uint32(lo>>48) | (uint32(hiByte) << 16)

	var z int32 = 0
	for i := 0; i < len(gaussian0Dist); i += 3 {
		w0 := gaussian0Dist[i+2]
		w1 := gaussian0Dist[i+1]
		w2 := gaussian0Dist[i]

		cc := (v0 - w0) >> 31
		cc = (v1 - w1 - cc) >> 31
		cc = (v2 - w2 - cc) >> 31

		z += int32(cc)
	}

	return 0, nil
}

func berExp(prng *samplerPRNG, x, ccs fpr) (bool, error) {
	s := int32(fprTrunc(fprMul(x, fprInvLog2)))
	r := fprSub(x, fprMul(fprOf(s), fprLog2))

	sw := uint32(s)
	sw ^= (sw ^ 63) & (uint32(0) - ((63 - sw) >> 31))
	s = int32(sw)

	z := ((fprExpmP63(r, ccs) << 1) - 1) >> uint(s)

	for i := uint(64); ; {
		i -= 8

		rb, err := prng.readByte()
		if err != nil {
			return false, err
		}

		w := uint32(rb) - uint32((z>>i)&0xFF)
		if w != 0 || i == 0 {
			return (w >> 31) != 0, nil
		}
	}
}

func sampleZ(prng *samplerPRNG, mu, isigma fpr) (int32, error) {
	s := int32(fprFloor(mu))
	r := fprSub(mu, fprOf(s))

	dss := fprHalf(fprSqr(isigma))
	css := fprMul(isigma, fprSigmaMin)

	for {
		z0, err := gaussian0Sampler(prng)
		if err != nil {
			return 0, err
		}

		rb, err := prng.readByte()
		if err != nil {
			return 0, err
		}

		b := int32(rb & 1)
		z := b + ((b<<1)-1)*z0

		x := fprMul(fprSqr(fprSub(fprOf(z), r)), dss)
		x = fprSub(x, fprMul(fprOf(z0*z0), fprInv2sqrsigma0))

		ok, err := berExp(prng, x, css)
		if err != nil {
			return 0, err
		}
		if ok {
			return s + z, nil
		}
	}
}

func ffSamplingFFTDynTree(
	prng *samplerPRNG,
	t0, t1 fprPoly,
	g00, g01, g11 fprPoly,
	origLogn, logn int,
) error {
	if logn == 0 {
		leaf := fprMul(fprSqrt(g00[0]), fprInvSigma[origLogn])

		z0, err := sampleZ(prng, t0[0], leaf)
		if err != nil {
			return err
		}
		z1, err := sampleZ(prng, t1[0], leaf)
		if err != nil {
			return err
		}

		t0[0] = fprOf(z0)
		t1[0] = fprOf(z1)
	}

	n := 1 << logn
	hn := n >> 1

	polyLDLFFTLogN(g00, g01, g11, logn)

	d00 := newFPRPoly()
	d11 := newFPRPoly()
	l10 := newFPRPoly()

	polySplitFFTLogN(d00[:hn], d00[hn:], g00, logn)
	polySplitFFTLogN(d11[:hn], d11[hn:], g11, logn)
	copy(l10, g01)

	z1 := make(fprPoly, n)
	polySplitFFTLogN(z1[:hn], z1[hn:], t1, logn)

	rightG11 := make(fprPoly, hn)
	copy(rightG11, d11[:hn])

	if err := ffSamplingFFTDynTree(
		prng,
		z1[:hn],
		z1[hn:],
		d11[:hn],
		d11[hn:],
		rightG11,
		origLogn,
		logn-1,
	); err != nil {
		return err
	}

	sampledT1 := make(fprPoly, n)
	polyMergeFFTLogN(sampledT1, z1[:hn], z1[hn:], logn)

	delta := make(fprPoly, n)
	copy(delta, t1)
	polySubLogN(delta, sampledT1, logn)

	copy(t1, sampledT1)
	correction := make(fprPoly, n)
	copy(correction, l10)
	polyMulFFTLogN(correction, delta, logn)
	polyAddLogN(t0, correction, logn)

	// Left subtree: split updated t0, sample, then merge back into t0.
	z0 := make(fprPoly, n)
	polySplitFFTLogN(z0[:hn], z0[hn:], t0, logn)

	leftG11 := make(fprPoly, hn)
	copy(leftG11, d00[:hn])

	if err := ffSamplingFFTDynTree(
		prng,
		z0[:hn],
		z0[hn:],
		d00[:hn],
		d00[hn:],
		leftG11,
		origLogn,
		logn-1,
	); err != nil {
		return err
	}

	polyMergeFFTLogN(t0, z0[:hn], z0[hn:], logn)

	return nil
}

func doSignDyn(prng *samplerPRNG, f, g, ntruF, ntruG, hm coeffPoly) (coeffPoly, bool) {
	b00 := newFPRPoly()
	b01 := newFPRPoly()
	b10 := newFPRPoly()
	b11 := newFPRPoly()

	smallIntsToFPR(b01, f)
	smallIntsToFPR(b00, g)
	smallIntsToFPR(b11, ntruF)
	smallIntsToFPR(b10, ntruG)

	fft(b01)
	fft(b00)
	fft(b11)
	fft(b10)

	polyNeg(b01)
	polyNeg(b11)

	g00 := newFPRPoly()
	g01 := newFPRPoly()
	g11 := newFPRPoly()
	tmp := newFPRPoly()

	copy(g00, b00)
	polyMulSelfAdjFFT(g00)
	copy(tmp, b01)
	polyMulSelfAdjFFT(tmp)
	polyAdd(g00, tmp)

	copy(g01, b00)
	polyMulAdjFFT(g01, b10)
	copy(tmp, b01)
	polyMulAdjFFT(tmp, b11)
	polyAdd(g01, tmp)

	copy(g11, b10)
	polyMulSelfAdjFFT(g11)
	copy(tmp, b11)
	polyMulSelfAdjFFT(tmp)
	polyAdd(g11, tmp)

	t0 := newFPRPoly()

	for i := range polyDegree {
		t0[i] = fprOf(hm[i])
	}
	fft(t0)

	t1 := newFPRPoly()
	copy(t1, t0)
	polyMulFFT(t1, b01)
	polyMulConst(t1, fprNeg(fprInverseOfQ))

	polyMulFFT(t0, b11)
	polyMulConst(t0, fprInverseOfQ)

	if err := ffSamplingFFTDynTree(prng, t0, t1, g00, g01, g11, logPolyDegree, logPolyDegree); err != nil {
		return nil, false
	}

	latticeX := newFPRPoly()
	latticeY := newFPRPoly()

	copy(latticeX, t0)
	polyMulFFT(latticeX, b00)
	copy(tmp, t1)
	polyMulFFT(tmp, b10)
	polyAdd(latticeX, tmp)

	copy(latticeY, t0)
	polyMulFFT(latticeY, b01)
	copy(tmp, t1)
	polyMulFFT(tmp, b11)
	polyAdd(latticeY, tmp)

	ifft(latticeX)
	ifft(latticeY)

	s2 := newCoeffPoly()

	var sqn uint32
	var ng uint32

	for i := range polyDegree {
		z := hm[i] - int32(fprRint(latticeX[i]))
		sqn += uint32(z * z)
		ng |= sqn

		s2[i] = -int32(fprRint(latticeY[i]))
	}

	sqn |= -(ng >> 31)

	if !isShortHalf(sqn, s2) {
		return nil, false
	}

	return s2, true
}

type samplerPRNG struct {
	rng sha3.ShakeHash
}

func newSamplerPRNG(rng sha3.ShakeHash) *samplerPRNG {
	return &samplerPRNG{rng: rng}
}

func (p *samplerPRNG) readByte() (byte, error) {
	var buf [1]byte
	if _, err := p.rng.Read(buf[:]); err != nil {
		return 0, err
	}
	return buf[0], nil
}

func (p *samplerPRNG) readUint64() (uint64, error) {
	var buf [8]byte
	if _, err := p.rng.Read(buf[:]); err != nil {
		return 0, err
	}

	return uint64(buf[0]) |
		uint64(buf[1])<<8 |
		uint64(buf[2])<<16 |
		uint64(buf[3])<<24 |
		uint64(buf[4])<<32 |
		uint64(buf[5])<<40 |
		uint64(buf[6])<<48 |
		uint64(buf[7])<<56, nil
}

func signDyn(rng sha3.ShakeHash, f, g, ntruF, ntruG, hm coeffPoly) (coeffPoly, error) {
	for {
		prng := newSamplerPRNG(rng)

		if sigp, ok := doSignDyn(prng, f, g, ntruF, ntruG, hm); ok {
			return sigp, nil
		}
	}
}
