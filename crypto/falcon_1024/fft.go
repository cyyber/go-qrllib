package falcon

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

func polyMulConst(a fprPoly, x fpr) {
	for i := range polyDegree {
		a[i] = fprMul(a[i], x)
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

func iftt(f fprPoly) {
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
