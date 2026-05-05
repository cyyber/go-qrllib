package falcon1024

import "math"

const fprInverseOfQ fpr = 1.0 / q

type fpr float64

func fprRint(x fpr) int64 {
	// TODO
	return 0
}

type fprPolynomial [n]fpr

func fprFromSmall(src smallPolynomial) fprPolynomial {
	dst := fprPolynomial{}

	for i := 0; i < n; i += 8 {
		dst[i+0] = fpr(src[i+0])
		dst[i+1] = fpr(src[i+1])
		dst[i+2] = fpr(src[i+2])
		dst[i+3] = fpr(src[i+3])
		dst[i+4] = fpr(src[i+4])
		dst[i+5] = fpr(src[i+5])
		dst[i+6] = fpr(src[i+6])
		dst[i+7] = fpr(src[i+7])
	}

	return dst
}

type fprTree [(logN + 1) * n]fpr

type fftPolynomial [n]fpr

const (
	falconSigmaMin1024  fpr = 1.2982803343442918539708792538826807
	falconInv2SqrSigma0 fpr = 0.150865048875372721532312163019
	falconInvSqrt2      fpr = 0.707106781186547524400844362105
	falconInvSqrt8      fpr = 0.353553390593273762200422181052
)

type u72 struct {
	hi byte
	lo uint64
}

var (
	fftGMRe, fftGMIm = initFFTGM()
	gaussian0CDF     = [...]u72{
		{hi: 0x00, lo: 0x0000000000000000},
		{hi: 0x00, lo: 0x00000000000000c5},
		{hi: 0x00, lo: 0x0000000000007097},
		{hi: 0x00, lo: 0x00000000002f5d7d},
		{hi: 0x00, lo: 0x000000000ebf6eba},
		{hi: 0x00, lo: 0x00000003665da997},
		{hi: 0x00, lo: 0x000000949f8b091e},
		{hi: 0x00, lo: 0x000012cf24d031fa},
		{hi: 0x00, lo: 0x0001c3fdb2040c68},
		{hi: 0x00, lo: 0x001f80d88a7b6427},
		{hi: 0x00, lo: 0x01a1ffdc65ad63d9},
		{hi: 0x00, lo: 0x1024dd542b776ae3},
		{hi: 0x00, lo: 0x774ac754ed74bd5e},
		{hi: 0x02, lo: 0x95846caef33f1f6e},
		{hi: 0x0a, lo: 0xd1754377c7994ae3},
		{hi: 0x22, lo: 0x7dcdd0934829c1fe},
		{hi: 0x54, lo: 0xd32b181f3f7ddb81},
		{hi: 0xa3, lo: 0xf7f42ed3ac391801},
		{hi: 0xff, lo: 0xffffffffffffffff},
	}
)

func initFFTGM() ([n]fpr, [n]fpr) {
	var re, im [n]fpr
	for j := 0; j < n; j++ {
		rev := 0
		x := j
		for i := 0; i < logN; i++ {
			rev = (rev << 1) | (x & 1)
			x >>= 1
		}
		sin, cos := math.Sincos(math.Pi * float64(rev) / float64(n))
		re[j] = fpr(cos)
		im[j] = fpr(sin)
	}
	return re, im
}

func gaussian0Sample(prng *samplerPRNG) int {
	lo := prng.readUint64()
	hi := prng.readByte()
	for i, bound := range gaussian0CDF {
		if hi < bound.hi || (hi == bound.hi && lo <= bound.lo) {
			return 18 - i
		}
	}
	return 0
}

func berExp(prng *samplerPRNG, x, ccs fpr) bool {
	p := float64(ccs) * math.Exp(-float64(x))
	if p >= 1 {
		return true
	}
	if p <= 0 {
		return false
	}
	const inv53 = 1.0 / 9007199254740992.0
	return float64(prng.readUint64()>>11)*inv53 < p
}

func sampleFFTPoint(prng *samplerPRNG, mu, isigma fpr) fpr {
	s := math.Floor(float64(mu))
	r := mu - fpr(s)
	dss := 0.5 * isigma * isigma
	ccs := falconSigmaMin1024 * isigma

	for {
		z0 := gaussian0Sample(prng)
		b := int(prng.readByte()) & 1
		z := b + ((b<<1)-1)*z0

		x := fpr(z) - r
		x = x*x*dss - fpr(z0*z0)*falconInv2SqrSigma0
		if berExp(prng, x, ccs) {
			return fpr(s + float64(z))
		}
	}
}

func ffLDLTreeSize(logn int) int {
	return (logn + 1) << logn
}

func mulFFTSlice(a, b []fpr) {
	hn := len(a) >> 1
	for u := 0; u < hn; u++ {
		aRe := a[u]
		aIm := a[u+hn]
		bRe := b[u]
		bIm := b[u+hn]
		a[u] = aRe*bRe - aIm*bIm
		a[u+hn] = aRe*bIm + aIm*bRe
	}
}

func splitFFTSlice(f0, f1, f []fpr, logn int) {
	nn := 1 << logn
	hn := nn >> 1
	qn := hn >> 1

	f0[0] = f[0]
	f1[0] = f[hn]

	for u := 0; u < qn; u++ {
		aRe := f[(u<<1)+0]
		aIm := f[(u<<1)+0+hn]
		bRe := f[(u<<1)+1]
		bIm := f[(u<<1)+1+hn]

		tRe := aRe + bRe
		tIm := aIm + bIm
		f0[u] = 0.5 * tRe
		f0[u+qn] = 0.5 * tIm

		tRe = aRe - bRe
		tIm = aIm - bIm
		gmRe := fftGMRe[u+hn]
		gmIm := -fftGMIm[u+hn]
		f1[u] = 0.5 * (tRe*gmRe - tIm*gmIm)
		f1[u+qn] = 0.5 * (tRe*gmIm + tIm*gmRe)
	}
}

func mergeFFTSlice(f, f0, f1 []fpr, logn int) {
	nn := 1 << logn
	hn := nn >> 1
	qn := hn >> 1

	f[0] = f0[0]
	f[hn] = f1[0]

	for u := 0; u < qn; u++ {
		aRe := f0[u]
		aIm := f0[u+qn]
		bRe := f1[u]
		bIm := f1[u+qn]
		gmRe := fftGMRe[u+hn]
		gmIm := fftGMIm[u+hn]
		cRe := bRe*gmRe - bIm*gmIm
		cIm := bRe*gmIm + bIm*gmRe

		f[(u<<1)+0] = aRe + cRe
		f[(u<<1)+0+hn] = aIm + cIm
		f[(u<<1)+1] = aRe - cRe
		f[(u<<1)+1+hn] = aIm - cIm
	}
}

func ffSamplingFFTRecursive(prng *samplerPRNG, z0, z1, tree, t0, t1, tmp []fpr, logn int) {
	if logn == 2 {
		tree0 := tree[4:]
		tree1 := tree[8:]

		aRe := t1[0]
		aIm := t1[2]
		bRe := t1[1]
		bIm := t1[3]

		cRe := aRe + bRe
		cIm := aIm + bIm
		w0 := 0.5 * cRe
		w1 := 0.5 * cIm

		cRe = aRe - bRe
		cIm = aIm - bIm
		w2 := (cRe + cIm) * falconInvSqrt8
		w3 := (cIm - cRe) * falconInvSqrt8

		x0 := w2
		x1 := w3
		w2 = sampleFFTPoint(prng, x0, tree1[3])
		w3 = sampleFFTPoint(prng, x1, tree1[3])

		aRe = x0 - w2
		aIm = x1 - w3
		bRe = tree1[0]
		bIm = tree1[1]
		cRe = aRe*bRe - aIm*bIm
		cIm = aRe*bIm + aIm*bRe
		x0 = cRe + w0
		x1 = cIm + w1

		w0 = sampleFFTPoint(prng, x0, tree1[2])
		w1 = sampleFFTPoint(prng, x1, tree1[2])

		aRe = w0
		aIm = w1
		bRe = w2
		bIm = w3
		cRe = (bRe - bIm) * falconInvSqrt2
		cIm = (bRe + bIm) * falconInvSqrt2
		z1[0] = aRe + cRe
		z1[2] = aIm + cIm
		z1[1] = aRe - cRe
		z1[3] = aIm - cIm

		w0 = t1[0] - z1[0]
		w1 = t1[1] - z1[1]
		w2 = t1[2] - z1[2]
		w3 = t1[3] - z1[3]

		aRe = w0
		aIm = w2
		bRe = tree[0]
		bIm = tree[2]
		w0 = aRe*bRe - aIm*bIm
		w2 = aRe*bIm + aIm*bRe

		aRe = w1
		aIm = w3
		bRe = tree[1]
		bIm = tree[3]
		w1 = aRe*bRe - aIm*bIm
		w3 = aRe*bIm + aIm*bRe

		w0 += t0[0]
		w1 += t0[1]
		w2 += t0[2]
		w3 += t0[3]

		aRe = w0
		aIm = w2
		bRe = w1
		bIm = w3

		cRe = aRe + bRe
		cIm = aIm + bIm
		w0 = 0.5 * cRe
		w1 = 0.5 * cIm

		cRe = aRe - bRe
		cIm = aIm - bIm
		w2 = (cRe + cIm) * falconInvSqrt8
		w3 = (cIm - cRe) * falconInvSqrt8

		x0 = w2
		x1 = w3
		w2 = sampleFFTPoint(prng, x0, tree0[3])
		w3 = sampleFFTPoint(prng, x1, tree0[3])

		aRe = x0 - w2
		aIm = x1 - w3
		bRe = tree0[0]
		bIm = tree0[1]
		cRe = aRe*bRe - aIm*bIm
		cIm = aRe*bIm + aIm*bRe
		x0 = cRe + w0
		x1 = cIm + w1

		w0 = sampleFFTPoint(prng, x0, tree0[2])
		w1 = sampleFFTPoint(prng, x1, tree0[2])

		aRe = w0
		aIm = w1
		bRe = w2
		bIm = w3
		cRe = (bRe - bIm) * falconInvSqrt2
		cIm = (bRe + bIm) * falconInvSqrt2
		z0[0] = aRe + cRe
		z0[2] = aIm + cIm
		z0[1] = aRe - cRe
		z0[3] = aIm - cIm
		return
	}

	if logn == 1 {
		x0 := t1[0]
		x1 := t1[1]
		z1[0] = sampleFFTPoint(prng, x0, tree[3])
		z1[1] = sampleFFTPoint(prng, x1, tree[3])

		aRe := x0 - z1[0]
		aIm := x1 - z1[1]
		bRe := tree[0]
		bIm := tree[1]
		cRe := aRe*bRe - aIm*bIm
		cIm := aRe*bIm + aIm*bRe

		z0[0] = sampleFFTPoint(prng, cRe+t0[0], tree[2])
		z0[1] = sampleFFTPoint(prng, cIm+t0[1], tree[2])
		return
	}

	if logn == 0 {
		isigma := tree[0]
		z0[0] = sampleFFTPoint(prng, t0[0], isigma)
		z1[0] = sampleFFTPoint(prng, t1[0], isigma)
		return
	}

	nn := 1 << logn
	hn := nn >> 1
	tree0 := tree[nn:]
	tree1 := tree[nn+ffLDLTreeSize(logn-1):]

	splitFFTSlice(z1[:hn], z1[hn:nn], t1[:nn], logn)
	ffSamplingFFTRecursive(prng, tmp[:hn], tmp[hn:nn], tree1, z1[:hn], z1[hn:nn], tmp[nn:], logn-1)
	mergeFFTSlice(z1[:nn], tmp[:hn], tmp[hn:nn], logn)

	copy(tmp[:nn], t1[:nn])
	for i := 0; i < nn; i++ {
		tmp[i] -= z1[i]
	}
	mulFFTSlice(tmp[:nn], tree[:nn])
	for i := 0; i < nn; i++ {
		tmp[i] += t0[i]
	}

	splitFFTSlice(z0[:hn], z0[hn:nn], tmp[:nn], logn)
	ffSamplingFFTRecursive(prng, tmp[:hn], tmp[hn:nn], tree0, z0[:hn], z0[hn:nn], tmp[nn:], logn-1)
	mergeFFTSlice(z0[:nn], tmp[:hn], tmp[hn:nn], logn)
}

func fft(f fprPolynomial) fftPolynomial {
	// TODO
	return fftPolynomial{}
}

func inverseFFT(fftPolynomial) fprPolynomial {
	// TODO
	return fprPolynomial{}
}

func fftMul(a, b fftPolynomial) (p fftPolynomial) {
	// TODO
	return a
}

func fftMulConst(a fftPolynomial, x fpr) (p fftPolynomial) {
	// TODO
	return a
}

func fftMulSelfAdj(a fftPolynomial) (p fftPolynomial) {
	// TODO
	return a
}

func ffSamplingFFT(prng *samplerPRNG, t0, t1 fftPolynomial, tree []fpr, logn int) (fftPolynomial, fftPolynomial, error) {
	var z0, z1 fftPolynomial
	var tmp [2 * n]fpr

	nn := 1 << logn
	ffSamplingFFTRecursive(prng, z0[:nn], z1[:nn], tree, t0[:nn], t1[:nn], tmp[:nn<<1], logn)

	return z0, z1, nil
}

func polyAdd[T ~[n]fpr](a, b T) (s T) {
	for i := range s {
		s[i] = a[i] + b[i]
	}
	return s
}

func polyNeg[T ~[n]fpr](a T) (p T) {
	for i := range p {
		p[i] = -a[i]
	}
	return p
}
