package falcon_1024

const (
	hn = polyDegree >> 1
)

func fpcAdd(aRe, aIm, bRe, bIm fpr) (fpr, fpr) {
	return fprAdd(aRe, bRe), fprAdd(aIm, bIm)
}

func fpcSub(aRe, aIm, bRe, bIm fpr) (fpr, fpr) {
	return fprSub(aRe, bRe), fprSub(aIm, bIm)

}

func fpcMul(aRe, aIm, bRe, bIm fpr) (fpr, fpr) {
	return fprSub(fprMul(aRe, bRe), fprMul(aIm, bIm)),
		fprAdd(fprMul(aRe, bIm), fprMul(aIm, bRe))
}

func fpcDiv(aRe, aIm, bRe, bIm fpr) (fpr, fpr) {
	fpctM := fprAdd(fprSqr(bRe), fprSqr(bIm))
	return fprMul(fprAdd(fprMul(aRe, bRe), fprMul(aIm, bIm)), fprInv(fpctM)),
		fprMul(fprSub(fprMul(aIm, bRe), fprMul(aRe, bIm)), fprInv(fpctM))
}

func polyInvNorm2FFT(d, a, b fprPoly) {
	for i := range hn {
		aRe := a[i]
		aIm := a[i+hn]
		bRe := b[i]
		bIm := b[i+hn]
		d[i] = fprInv(fprAdd(
			fprAdd(fprSqr(aRe), fprSqr(aIm)),
			fprAdd(fprSqr(bRe), fprSqr(bIm)),
		))
	}
}

func polyAdjFFT(a fprPoly) {
	for i := (polyDegree >> 1); i < polyDegree; i++ {
		a[i] = fprNeg(a[i])
	}
}

func polyMulAutoAdjFFT(a, b fprPoly) {
	for i := range hn {
		a[i] = fprMul(a[i], b[i])
		a[i+hn] = fprMul(a[i+hn], b[i])
	}
}

func polyMulSelfAdjFFT(a fprPoly) {
	for u := range hn {
		aRe := a[u]
		aIm := a[u+hn]
		a[u] = fprAdd(fprSqr(aRe), fprSqr(aIm))
		a[u+hn] = fprZero
	}
}

func polyMulAdjFFT(a, b fprPoly) {
	for u := range hn {
		aRe := a[u]
		aIm := a[u+hn]
		bRe := b[u]
		bIm := fprNeg(b[u+hn])
		a[u], a[u+hn] = fpcMul(aRe, aIm, bRe, bIm)
	}
}

func polyMulFFT(a, b fprPoly) {
	for i := range hn {
		aRe := a[i]
		aIm := a[i+hn]
		bRe := b[i]
		bIm := b[i+hn]
		a[i], a[i+hn] = fpcMul(aRe, aIm, bRe, bIm)
	}
}

func polyMulFFTLogN(a, b fprPoly, logn int) {
	n := 1 << logn
	hn := n >> 1
	for i := range hn {
		aRe := a[i]
		aIm := a[i+hn]
		bRe := b[i]
		bIm := b[i+hn]
		a[i], a[i+hn] = fpcMul(aRe, aIm, bRe, bIm)
	}
}

func polyMulConst(a fprPoly, x fpr) {
	for i := range polyDegree {
		a[i] = fprMul(a[i], x)
	}
}

func polyNeg(a fprPoly) {
	for u := range polyDegree {
		a[u] = fprNeg(a[u])
	}
}

func polyAdd(a, b fprPoly) {
	for u := range polyDegree {
		a[u] = fprAdd(a[u], b[u])
	}
}

func polyAddLogN(a, b fprPoly, logn int) {
	for u := range 1 << logn {
		a[u] = fprAdd(a[u], b[u])
	}
}

func polySubLogN(a, b fprPoly, logn int) {
	n := 1 << logn
	for i := range n {
		a[i] = fprSub(a[i], b[i])
	}
}

func polyLDLFFTLogN(g00, g01, g11 fprPoly, logn int) {
	n := 1 << logn
	hn := n >> 1

	for i := range hn {
		g00Re := g00[i]
		g00Im := g00[i+hn]
		g01Re := g01[i]
		g01Im := g01[i+hn]
		g11Re := g11[i]
		g11Im := g11[i+hn]

		muRe, muIm := fpcDiv(g01Re, g01Im, g00Re, g00Im)
		xRe, xIm := fpcMul(muRe, muIm, g01Re, fprNeg(g01Im))

		g11[i], g11[i+hn] = fpcSub(g11Re, g11Im, xRe, xIm)
		g01[i] = muRe
		g01[i+hn] = fprNeg(muIm)
	}
}

func fft(f fprPoly) {
	t := polyDegree >> 1
	for u, m := 1, 2; u < logPolyDegree; u, m = u+1, m<<1 {
		ht := t >> 1
		hm := m >> 1
		for i1, j1 := 0, 0; i1 < hm; i1, j1 = i1+1, j1+t {
			j2 := j1 + ht
			sRe := fprGmTab[((m+i1)<<1)+0]
			sIm := fprGmTab[((m+i1)<<1)+1]
			for j := j1; j < j2; j++ {
				xRe := f[j]
				xIm := f[j+hn]
				yRe := f[j+ht]
				yIm := f[j+ht+hn]
				yRe, yIm = fpcMul(yRe, yIm, sRe, sIm)
				f[j], f[j+hn] = fpcAdd(xRe, xIm, yRe, yIm)
				f[j+ht], f[j+ht+hn] = fpcSub(xRe, xIm, yRe, yIm)
			}
		}
		t = ht
	}
}

func ifft(f fprPoly) {
	t := 1
	m := polyDegree
	for u := logPolyDegree; u > 1; u-- {
		hm := m >> 1
		dt := t << 1
		for i1, j1 := 0, 0; j1 < hn; i1, j1 = i1+1, j1+dt {
			j2 := j1 + t
			sre := fprGmTab[((hm+i1)<<1)+0]
			sim := fprNeg(fprGmTab[((hm+i1)<<1)+1])
			for j := j1; j < j2; j++ {
				xre := f[j]
				xim := f[j+hn]
				yre := f[j+t]
				yim := f[j+t+hn]
				f[j], f[j+hn] = fpcAdd(xre, xim, yre, yim)
				xre, xim = fpcSub(xre, xim, yre, yim)
				f[j+t], f[j+t+hn] = fpcMul(xre, xim, sre, sim)
			}
		}
		t = dt
		m = hm
	}

	for u := range polyDegree {
		f[u] = fprMul(f[u], fprP2)
	}
}

func polySplitFFTLogN(f0, f1, f fprPoly, logn int) {
	n := 1 << logn
	hn := n >> 1
	qn := hn >> 1

	f0[0] = f[0]
	f1[0] = f[hn]

	for i := range qn {
		aRe := f[(i<<1)+0]
		aIm := f[(i<<1)+0+hn]
		bRe := f[(i<<1)+1]
		bIm := f[(i<<1)+1+hn]

		tRe, tIm := fpcAdd(aRe, aIm, bRe, bIm)
		f0[i] = fprHalf(tRe)
		f0[i+qn] = fprHalf(tIm)

		tRe, tIm = fpcSub(aRe, aIm, bRe, bIm)
		tRe, tIm = fpcMul(
			tRe,
			tIm,
			fprGmTab[((i+hn)<<1)+0],
			fprNeg(fprGmTab[((i+hn)<<1)+1]),
		)

		f1[i] = fprHalf(tRe)
		f1[i+qn] = fprHalf(tIm)
	}
}

func polyMergeFFTLogN(f, f0, f1 fprPoly, logn int) {
	n := 1 << logn
	hn := n >> 1
	qn := hn >> 1

	if qn == 0 {
		f[0] = f0[0]
		f[hn] = f1[0]
		return
	}

	for i := range qn {
		aRe := f0[i]
		aIm := f0[i+qn]
		bRe := f1[i]
		bIm := f1[i+qn]

		bRe, bIm = fpcMul(
			bRe,
			bIm,
			fprGmTab[((i+hn)<<1)+0],
			fprGmTab[((i+hn)<<1)+1],
		)

		f[(i<<1)+0] = fprAdd(aRe, bRe)
		f[(i<<1)+0+hn] = fprAdd(aIm, bIm)
		f[(i<<1)+1] = fprSub(aRe, bRe)
		f[(i<<1)+1+hn] = fprSub(aIm, bIm)
	}
}
