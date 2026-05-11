package falcon1024

import "math"

const ntruCoeffBound = 127

func solveNTRU(f, g smallPolynomial) (ntruF, ntruG smallPolynomial, ok bool) {
	wk := newNTRUWorkspace()

	if !solveNTRUDeepest(f, g, wk.state) {
		return smallPolynomial{}, smallPolynomial{}, false
	}

	for depth := logN; depth > 2; {
		depth--
		if !solveNTRUIntermediate(f, g, depth, wk) {
			return smallPolynomial{}, smallPolynomial{}, false
		}
	}
	if !solveNTRUBinaryDepth1(f, g, wk) {
		return smallPolynomial{}, smallPolynomial{}, false
	}
	if !solveNTRUBinaryDepth0(f, g, wk) {
		return smallPolynomial{}, smallPolynomial{}, false
	}

	ntruF, ok = polyBigToSmall(wk.state[:n], ntruCoeffBound)
	if !ok {
		return smallPolynomial{}, smallPolynomial{}, false
	}
	ntruG, ok = polyBigToSmall(wk.state[n:2*n], ntruCoeffBound)
	if !ok {
		return smallPolynomial{}, smallPolynomial{}, false
	}
	if !checkNTRUEquation(f, g, ntruF, ntruG, wk.scratch) {
		return smallPolynomial{}, smallPolynomial{}, false
	}
	return ntruF, ntruG, true
}

// Scratch lengths are implementation workspace capacities derived from the Go
// NTRU scratch slicing below, not Falcon parameters. Revalidate them if any
// NTRU stage changes its scratch layout.
const (
	ntruScratchLen             = 7 * n
	makeFGScratchLen           = 6 * n
	polySubScaledNTTScratchLen = 1536
	ntruU32ScratchLen          = 16 * n
	ntruFPRScratchLen          = 8 * n

	// Sizes below are the maximum buffers solveNTRUIntermediate / its lift &
	// reduce helpers need across the depths they actually run at (2..logN-1).
	// Each comment annotates which depth saturates the maximum.
	ntruInterFdGdMax = 256  // max(dlen*hn) at depth 2 and 3 (tied)
	ntruInterFtGtMax = 1280 // max(n*llen)  at depth 2
	ntruInterNMax    = 256  // max n         at depth 2
)

// ntruWorkspace mirrors the Falcon reference tmp scratch model, but keeps
// uint32 and fpr scratch storage separate for Go type safety. All buffers are
// owned by the workspace so per-keygen helpers can borrow slices without
// allocating.
type ntruWorkspace struct {
	state   []uint32 // persistent NTRU solution/state across stages
	scratch []uint32 // generic uint32 scratch (newUint32Scratch consumers)
	fpr     []fpr    // generic fpr scratch    (newFPRScratch consumers)

	// makeFGPair scratch + result region.
	makeFGScratch []uint32 // 6*N, used by makeFG and the ft/gt slices it leaves behind

	// solveNTRUIntermediate persistent buffers (must outlive lift+reduce calls).
	Fd, Gd []uint32 // dlen*hn snapshot of wk.state from the previous depth
	Ft, Gt []uint32 // n*llen lifted solution

	// reduceNTRUSolution k buffer (int32, separate from wk.scratch).
	k []int32
}

func newNTRUWorkspace() *ntruWorkspace {
	return &ntruWorkspace{
		state:         make([]uint32, ntruScratchLen),
		scratch:       make([]uint32, ntruU32ScratchLen),
		fpr:           make([]fpr, ntruFPRScratchLen),
		makeFGScratch: make([]uint32, makeFGScratchLen),
		Fd:            make([]uint32, ntruInterFdGdMax),
		Gd:            make([]uint32, ntruInterFdGdMax),
		Ft:            make([]uint32, ntruInterFtGtMax),
		Gt:            make([]uint32, ntruInterFtGtMax),
		k:             make([]int32, ntruInterNMax),
	}
}

type uint32Scratch struct {
	buf []uint32
	off int
}

func newUint32Scratch(buf []uint32) uint32Scratch {
	return uint32Scratch{buf: buf}
}

func (s *uint32Scratch) take(size int) []uint32 {
	out := s.buf[s.off : s.off+size]
	s.off += size
	return out
}

func (s *uint32Scratch) takeCopy(src []uint32) []uint32 {
	out := s.take(len(src))
	copy(out, src)
	return out
}

type fprScratch struct {
	buf []fpr
	off int
}

func newFPRScratch(buf []fpr) fprScratch {
	return fprScratch{buf: buf}
}

func (s *fprScratch) take(size int) []fpr {
	out := s.buf[s.off : s.off+size]
	s.off += size
	return out
}

func checkNTRUEquation(f, g, ntruF, ntruG smallPolynomial, scratch []uint32) bool {
	p := primes[0].p
	p0i := modPNInv31(p)
	gm := scratch[:n]
	igm := scratch[n : 2*n]
	modPMkgm2(gm, igm, logN, primes[0].g, p, p0i)

	ft := scratch[2*n : 3*n]
	gt := scratch[3*n : 4*n]
	Ft := scratch[4*n : 5*n]
	Gt := scratch[5*n : 6*n]
	for i := range n {
		ft[i] = modPSet(f[i], p)
		gt[i] = modPSet(g[i], p)
		Ft[i] = modPSet(ntruF[i], p)
		Gt[i] = modPSet(ntruG[i], p)
	}

	modPNTT2(ft, logN, gm, p, p0i)
	modPNTT2(gt, logN, gm, p, p0i)
	modPNTT2(Ft, logN, gm, p, p0i)
	modPNTT2(Gt, logN, gm, p, p0i)

	target := modPMontyMul(q, 1, p, p0i)
	for i := range n {
		z := modPSub(
			modPMontyMul(ft[i], Gt[i], p, p0i),
			modPMontyMul(gt[i], Ft[i], p, p0i),
			p,
		)
		if z != target {
			return false
		}
	}
	return true
}

func makeFG(data []uint32, f, g smallPolynomial, depth int, outNTT bool) {
	nn := 1 << logN
	ft := data[:nn]
	gt := data[nn : 2*nn]
	p0 := primes[0].p
	for i := range nn {
		ft[i] = modPSet(f[i], p0)
		gt[i] = modPSet(g[i], p0)
	}

	if depth == 0 && outNTT {
		p := primes[0].p
		p0i := modPNInv31(p)
		gm := data[2*nn : 3*nn]
		igm := data[3*nn : 4*nn]
		modPMkgm2(gm, igm, logN, primes[0].g, p, p0i)
		modPNTT2(ft, logN, gm, p, p0i)
		modPNTT2(gt, logN, gm, p, p0i)
		return
	}
	for d := range depth {
		makeFGStep(data, logN-d, d, d != 0, (d+1) < depth || outNTT)
	}
}

func makeFGStep(data []uint32, logn, depth int, inNTT, outNTT bool) {
	nn := 1 << logn
	hn := nn >> 1
	slen := maxBlSmall[depth]
	tlen := maxBlSmall[depth+1]

	fd := data[:hn*tlen]
	gd := data[hn*tlen : 2*hn*tlen]
	fs := data[2*hn*tlen : 2*hn*tlen+nn*slen]
	gs := data[2*hn*tlen+nn*slen : 2*hn*tlen+2*nn*slen]
	gm := data[2*hn*tlen+2*nn*slen : 2*hn*tlen+2*nn*slen+nn]
	igm := data[2*hn*tlen+2*nn*slen+nn : 2*hn*tlen+2*nn*slen+2*nn]
	t1 := data[2*hn*tlen+2*nn*slen+2*nn : 2*hn*tlen+2*nn*slen+3*nn]

	copy(data[2*hn*tlen:2*hn*tlen+2*nn*slen], data[:2*nn*slen])
	for u := range slen {
		p := primes[u].p
		p0i := modPNInv31(p)
		r2 := modPR2(p, p0i)
		modPMkgm2(gm, igm, logn, primes[u].g, p, p0i)

		for v, x := 0, u; v < nn; v, x = v+1, x+slen {
			t1[v] = fs[x]
		}
		if !inNTT {
			modPNTT2(t1, logn, gm, p, p0i)
		}
		for v, x := 0, u; v < hn; v, x = v+1, x+tlen {
			w0 := t1[v<<1]
			w1 := t1[(v<<1)+1]
			fd[x] = modPMontyMul(modPMontyMul(w0, w1, p, p0i), r2, p, p0i)
		}
		if inNTT {
			modPINTT2Ext(fs[u:], slen, logn, igm, p, p0i)
		}

		for v, x := 0, u; v < nn; v, x = v+1, x+slen {
			t1[v] = gs[x]
		}
		if !inNTT {
			modPNTT2(t1, logn, gm, p, p0i)
		}
		for v, x := 0, u; v < hn; v, x = v+1, x+tlen {
			w0 := t1[v<<1]
			w1 := t1[(v<<1)+1]
			gd[x] = modPMontyMul(modPMontyMul(w0, w1, p, p0i), r2, p, p0i)
		}
		if inNTT {
			modPINTT2Ext(gs[u:], slen, logn, igm, p, p0i)
		}

		if !outNTT {
			modPINTT2Ext(fd[u:], tlen, logn-1, igm, p, p0i)
			modPINTT2Ext(gd[u:], tlen, logn-1, igm, p, p0i)
		}
	}

	scratchOff := 2*hn*tlen + 2*nn*slen + 3*nn
	crtScratch := t1
	if len(crtScratch) < slen {
		crtScratch = data[scratchOff : scratchOff+slen]
	}
	crtScratch = crtScratch[:slen]
	zintRebuildCRT(fs, slen, slen, nn, primes[:], true, crtScratch)
	zintRebuildCRT(gs, slen, slen, nn, primes[:], true, crtScratch)

	for u := slen; u < tlen; u++ {
		p := primes[u].p
		p0i := modPNInv31(p)
		r2 := modPR2(p, p0i)
		rx := modPRx(slen, p, p0i, r2)
		modPMkgm2(gm, igm, logn, primes[u].g, p, p0i)

		for v, x := 0, 0; v < nn; v, x = v+1, x+slen {
			t1[v] = zintModSmallSigned(fs[x:x+slen], p, p0i, r2, rx)
		}
		modPNTT2(t1, logn, gm, p, p0i)
		for v, x := 0, u; v < hn; v, x = v+1, x+tlen {
			w0 := t1[v<<1]
			w1 := t1[(v<<1)+1]
			fd[x] = modPMontyMul(modPMontyMul(w0, w1, p, p0i), r2, p, p0i)
		}

		for v, x := 0, 0; v < nn; v, x = v+1, x+slen {
			t1[v] = zintModSmallSigned(gs[x:x+slen], p, p0i, r2, rx)
		}
		modPNTT2(t1, logn, gm, p, p0i)
		for v, x := 0, u; v < hn; v, x = v+1, x+tlen {
			w0 := t1[v<<1]
			w1 := t1[(v<<1)+1]
			gd[x] = modPMontyMul(modPMontyMul(w0, w1, p, p0i), r2, p, p0i)
		}

		if !outNTT {
			modPINTT2Ext(fd[u:], tlen, logn-1, igm, p, p0i)
			modPINTT2Ext(gd[u:], tlen, logn-1, igm, p, p0i)
		}
	}
}

func solveNTRUDeepest(f, g smallPolynomial, tmp []uint32) bool {
	wordLen := maxBlSmall[logN]

	Fp := tmp[:wordLen]
	Gp := tmp[wordLen : 2*wordLen]

	resultants := tmp[2*wordLen:]
	fp := resultants[:wordLen]
	gp := resultants[wordLen : 2*wordLen]
	scratch := tmp[4*wordLen:]

	makeFG(resultants, f, g, logN, false)
	zintRebuildCRT(resultants, wordLen, wordLen, 2, primes[:], false, scratch)

	if !zintBezout(Gp, Fp, fp, gp, scratch) {
		return false
	}

	if zintMulSmall(Fp, q) != 0 || zintMulSmall(Gp, q) != 0 {
		return false
	}

	return true
}

func polyBigToFP(dst []fpr, src []uint32, wordLen, stride, logn int) {
	nn := 1 << logn
	if wordLen == 0 {
		clear(dst[:nn])
		return
	}
	for i := range nn {
		x := src[i*stride:]
		neg := -(x[wordLen-1] >> 30)
		xm := neg >> 1
		cc := neg & 1
		var y fpr
		scale := fpr(1)
		for j := range wordLen {
			w := (x[j] ^ xm) + cc
			cc = w >> 31
			w &= zintWordMask
			w -= (w << 1) & neg
			y += fpr(int32(w)) * scale
			scale *= 2147483648.0
		}
		dst[i] = y
	}
}

func polyBigToSmall(src []uint32, bound int) (smallPolynomial, bool) {
	var dst smallPolynomial
	for i := range dst {
		x := zintOneToPlain(src[i])
		if x < int32(-bound) || x > int32(bound) {
			return smallPolynomial{}, false
		}
		dst[i] = x
	}
	return dst, true
}

func polySubScaled(F []uint32, Flen, Fstride int, f []uint32, flen, fstride int, k []int32, sch, scl uint32, logn int) {
	nn := 1 << logn
	for u := range nn {
		kf := -k[u]
		x := u * Fstride
		for v := range nn {
			zintAddScaledMulSmall(F[x:x+Flen], f[v*fstride:v*fstride+flen], kf, sch, scl)
			if u+v == nn-1 {
				x = 0
				kf = -kf
			} else {
				x += Fstride
			}
		}
	}
}

func polySubScaledNTT(F []uint32, Flen, Fstride int, f []uint32, flen, fstride int, k []int32, sch, scl uint32, logn int, tmp []uint32) {
	nn := 1 << logn
	tlen := flen + 1
	gm := tmp[:nn]
	igm := tmp[nn : 2*nn]
	fk := tmp[2*nn : 2*nn+nn*tlen]
	t1 := tmp[2*nn+nn*tlen : 3*nn+nn*tlen]
	for u := range tlen {
		p := primes[u].p
		p0i := modPNInv31(p)
		r2 := modPR2(p, p0i)
		rx := modPRx(flen, p, p0i, r2)
		modPMkgm2(gm, igm, logn, primes[u].g, p, p0i)
		for v := range nn {
			t1[v] = modPSet(k[v], p)
		}
		modPNTT2(t1, logn, gm, p, p0i)

		for v, x := 0, u; v < nn; v, x = v+1, x+tlen {
			fk[x] = zintModSmallSigned(f[v*fstride:v*fstride+flen], p, p0i, r2, rx)
		}
		modPNTT2Ext(fk[u:], tlen, logn, gm, p, p0i)

		for v, x := 0, u; v < nn; v, x = v+1, x+tlen {
			fk[x] = modPMontyMul(modPMontyMul(t1[v], fk[x], p, p0i), r2, p, p0i)
		}
		modPINTT2Ext(fk[u:], tlen, logn, igm, p, p0i)
	}

	zintRebuildCRT(fk, tlen, tlen, nn, primes[:], true, t1)
	for u := range nn {
		zintSubScaled(F[u*Fstride:u*Fstride+Flen], fk[u*tlen:u*tlen+tlen], sch, scl)
	}
}

func solveNTRUIntermediate(f, g smallPolynomial, depth int, wk *ntruWorkspace) bool {
	logn := logN - depth
	n := 1 << logn
	hn := n >> 1

	slen := maxBlSmall[depth]
	dlen := maxBlSmall[depth+1]
	llen := maxBlLarge[depth]

	// Snapshot the previous depth's solution out of wk.state before lift /
	// reduce overwrites it.
	Fd := wk.Fd[:dlen*hn]
	Gd := wk.Gd[:dlen*hn]
	copy(Fd, wk.state[:dlen*hn])
	copy(Gd, wk.state[dlen*hn:2*dlen*hn])

	ft, gt := makeFGPair(wk, f, g, depth)

	Ft := wk.Ft[:n*llen]
	Gt := wk.Gt[:n*llen]

	if !liftNTRUSolution(wk, Ft, Gt, Fd, Gd, ft, gt, logn, slen, dlen, llen) {
		return false
	}

	if !reduceNTRUSolution(wk, Ft, Gt, ft, gt, depth, logn, slen, llen) {
		return false
	}
	writeReducedNTRUSolution(wk.state, Ft, Gt, n, slen, llen)
	return true
}

// makeFGPair returns ft / gt slices into wk.makeFGScratch. The slices are
// valid until wk.makeFGScratch is reused (i.e. until the next makeFGPair call
// inside this solveNTRU pass), which the caller controls.
func makeFGPair(wk *ntruWorkspace, f, g smallPolynomial, depth int) (ft, gt []uint32) {
	logn := logN - depth
	n := 1 << logn
	slen := maxBlSmall[depth]

	data := wk.makeFGScratch[:makeFGScratchLen]
	makeFG(data, f, g, depth, true)

	return data[:n*slen], data[n*slen : 2*n*slen]
}

func liftNTRUSolution(wk *ntruWorkspace, Ft, Gt, Fd, Gd, ft, gt []uint32, logn, slen, dlen, llen int) bool {
	n := 1 << logn
	hn := n >> 1

	u32s := newUint32Scratch(wk.scratch)
	gm := u32s.take(n)
	igm := u32s.take(n)
	fx := u32s.take(n)
	gx := u32s.take(n)
	Fp := u32s.take(hn)
	Gp := u32s.take(hn)
	crtScratch := u32s.take(max(llen, slen))

	for u := range llen {
		p := primes[u].p
		p0i := modPNInv31(p)
		r2 := modPR2(p, p0i)
		rx := modPRx(dlen, p, p0i, r2)
		for v := range hn {
			Ft[v*llen+u] = zintModSmallSigned(Fd[v*dlen:v*dlen+dlen], p, p0i, r2, rx)
			Gt[v*llen+u] = zintModSmallSigned(Gd[v*dlen:v*dlen+dlen], p, p0i, r2, rx)
		}
	}

	for u := range llen {
		p := primes[u].p
		p0i := modPNInv31(p)
		r2 := modPR2(p, p0i)
		modPMkgm2(gm, igm, logn, primes[u].g, p, p0i)

		if u == slen {
			zintRebuildCRT(ft, slen, slen, n, primes[:], true, crtScratch[:slen])
			zintRebuildCRT(gt, slen, slen, n, primes[:], true, crtScratch[:slen])
		}

		if u < slen {
			for v := range n {
				fx[v] = ft[v*slen+u]
				gx[v] = gt[v*slen+u]
			}
			modPINTT2Ext(ft[u:], slen, logn, igm, p, p0i)
			modPINTT2Ext(gt[u:], slen, logn, igm, p, p0i)
		} else {
			rx := modPRx(slen, p, p0i, r2)
			for v := range n {
				fx[v] = zintModSmallSigned(ft[v*slen:v*slen+slen], p, p0i, r2, rx)
				gx[v] = zintModSmallSigned(gt[v*slen:v*slen+slen], p, p0i, r2, rx)
			}
			modPNTT2(fx, logn, gm, p, p0i)
			modPNTT2(gx, logn, gm, p, p0i)
		}

		for v := range hn {
			Fp[v] = Ft[v*llen+u]
			Gp[v] = Gt[v*llen+u]
		}
		modPNTT2(Fp, logn-1, gm, p, p0i)
		modPNTT2(Gp, logn-1, gm, p, p0i)
		for v := range hn {
			ftA := fx[v<<1]
			ftB := fx[(v<<1)+1]
			gtA := gx[v<<1]
			gtB := gx[(v<<1)+1]
			mFp := modPMontyMul(Fp[v], r2, p, p0i)
			mGp := modPMontyMul(Gp[v], r2, p, p0i)
			Ft[(v<<1)*llen+u] = modPMontyMul(gtB, mFp, p, p0i)
			Ft[((v<<1)+1)*llen+u] = modPMontyMul(gtA, mFp, p, p0i)
			Gt[(v<<1)*llen+u] = modPMontyMul(ftB, mGp, p, p0i)
			Gt[((v<<1)+1)*llen+u] = modPMontyMul(ftA, mGp, p, p0i)
		}
		modPINTT2Ext(Ft[u:], llen, logn, igm, p, p0i)
		modPINTT2Ext(Gt[u:], llen, logn, igm, p, p0i)
	}

	zintRebuildCRT(Ft, llen, llen, n, primes[:], true, crtScratch[:llen])
	zintRebuildCRT(Gt, llen, llen, n, primes[:], true, crtScratch[:llen])
	return true
}

const depthIntFG = 4

func reduceNTRUSolution(wk *ntruWorkspace, Ft, Gt, ft, gt []uint32, depth, logn, slen, llen int) bool {
	n := 1 << logn

	fprs := newFPRScratch(wk.fpr)
	rt1 := fprs.take(n)
	rt2 := fprs.take(n)
	rt3 := fprs.take(n)
	rt4 := fprs.take(n)
	rt5 := fprs.take(n >> 1)

	u32s := newUint32Scratch(wk.scratch)
	scaledNTT := u32s.take(polySubScaledNTTScratchLen)

	k := wk.k[:n]

	rlen := min(slen, 10)
	polyBigToFP(rt3, ft[slen-rlen:], rlen, slen, logn)
	polyBigToFP(rt4, gt[slen-rlen:], rlen, slen, logn)
	scaleFGBase := 31 * (slen - rlen)

	minBitsFG := bitLength[depth].avg - 6*bitLength[depth].std
	maxBitsFG := bitLength[depth].avg + 6*bitLength[depth].std

	fftSlice(rt3, logn)
	fftSlice(rt4, logn)
	fftInvNorm2(rt5, rt3, rt4, logn)
	fftAdj(rt3, logn)
	fftAdj(rt4, logn)

	FGlen := llen
	maxBitsFGSolution := 31 * llen
	scaleK := maxBitsFGSolution - minBitsFG

	for {
		rlen = min(FGlen, 10)
		scaleFGSolution := 31 * (FGlen - rlen)
		polyBigToFP(rt1, Ft[FGlen-rlen:], rlen, llen, logn)
		polyBigToFP(rt2, Gt[FGlen-rlen:], rlen, llen, logn)

		fftSlice(rt1, logn)
		fftSlice(rt2, logn)
		fftMulSlice(rt1, rt3, logn)
		fftMulSlice(rt2, rt4, logn)
		fftAdd(rt2, rt1, logn)
		fftMulAutoAdj(rt2, rt5, logn)
		inverseFFTSlice(rt2, logn)

		scaleCorrection := scaleK - scaleFGSolution + scaleFGBase
		pdc := fpr(math.Ldexp(1, -scaleCorrection))
		for i := range n {
			x := rt2[i] * pdc
			if !(-2147483647.0 < x) || !(x < 2147483647.0) {
				return false
			}
			k[i] = int32(fprRint(x))
		}

		sch := uint32(scaleK / 31)
		scl := uint32(scaleK % 31)
		if depth <= depthIntFG {
			polySubScaledNTT(Ft, FGlen, llen, ft, slen, slen, k, sch, scl, logn, scaledNTT)
			polySubScaledNTT(Gt, FGlen, llen, gt, slen, slen, k, sch, scl, logn, scaledNTT)
		} else {
			polySubScaled(Ft, FGlen, llen, ft, slen, slen, k, sch, scl, logn)
			polySubScaled(Gt, FGlen, llen, gt, slen, slen, k, sch, scl, logn)
		}

		newMaxBitsFGSolution := scaleK + maxBitsFG + 10
		if newMaxBitsFGSolution < maxBitsFGSolution {
			maxBitsFGSolution = newMaxBitsFGSolution
			if FGlen*31 >= maxBitsFGSolution+31 {
				FGlen--
			}
		}

		if scaleK <= 0 {
			break
		}
		scaleK -= 25
		if scaleK < 0 {
			scaleK = 0
		}
	}

	if FGlen < slen {
		for i := range n {
			Fw := -(Ft[i*llen+FGlen-1] >> 30) >> 1
			Gw := -(Gt[i*llen+FGlen-1] >> 30) >> 1
			for j := FGlen; j < slen; j++ {
				Ft[i*llen+j] = Fw
				Gt[i*llen+j] = Gw
			}
		}
	}
	return true
}

func writeReducedNTRUSolution(tmp, Ft, Gt []uint32, n, slen, llen int) {
	for i := range n {
		copy(tmp[i*slen:(i+1)*slen], Ft[i*llen:i*llen+slen])
		copy(tmp[(n+i)*slen:(n+i+1)*slen], Gt[i*llen:i*llen+slen])
	}
}

func solveNTRUBinaryDepth0(f, g smallPolynomial, wk *ntruWorkspace) bool {
	nn := n
	hn := nn >> 1
	p := primes[0].p
	p0i := modPNInv31(p)
	r2 := modPR2(p, p0i)

	tmp := wk.state
	u32s := newUint32Scratch(wk.scratch)
	fprs := newFPRScratch(wk.fpr)

	prevF := u32s.takeCopy(tmp[:hn])
	prevG := u32s.takeCopy(tmp[hn:nn])
	Fp := u32s.take(nn)
	Gp := u32s.take(nn)
	ft := u32s.take(nn)
	gt := u32s.take(nn)
	gm := u32s.take(nn)
	igm := u32s.take(nn)

	modPMkgm2(gm, igm, logN, primes[0].g, p, p0i)
	for i := range hn {
		prevF[i] = modPSet(zintOneToPlain(prevF[i]), p)
		prevG[i] = modPSet(zintOneToPlain(prevG[i]), p)
	}
	modPNTT2(prevF, logN-1, gm, p, p0i)
	modPNTT2(prevG, logN-1, gm, p, p0i)
	for i := range nn {
		ft[i] = modPSet(f[i], p)
		gt[i] = modPSet(g[i], p)
	}
	modPNTT2(ft, logN, gm, p, p0i)
	modPNTT2(gt, logN, gm, p, p0i)

	for i := 0; i < nn; i += 2 {
		ftA := ft[i]
		ftB := ft[i+1]
		gtA := gt[i]
		gtB := gt[i+1]
		mFp := modPMontyMul(prevF[i>>1], r2, p, p0i)
		mGp := modPMontyMul(prevG[i>>1], r2, p, p0i)
		Fp[i] = modPMontyMul(gtB, mFp, p, p0i)
		Fp[i+1] = modPMontyMul(gtA, mFp, p, p0i)
		Gp[i] = modPMontyMul(ftB, mGp, p, p0i)
		Gp[i+1] = modPMontyMul(ftA, mGp, p, p0i)
	}
	modPINTT2(Fp, logN, igm, p, p0i)
	modPINTT2(Gp, logN, igm, p, p0i)

	modPNTT2(Fp, logN, gm, p, p0i)
	modPNTT2(Gp, logN, gm, p, p0i)

	t2 := u32s.take(nn)
	t3 := u32s.take(nn)
	t4 := u32s.take(nn)
	t5 := u32s.take(nn)

	t4[0] = modPSet(f[0], p)
	t5[0] = t4[0]
	for i := 1; i < nn; i++ {
		t4[i] = modPSet(f[i], p)
		t5[nn-i] = modPSet(-f[i], p)
	}
	modPNTT2(t4, logN, gm, p, p0i)
	modPNTT2(t5, logN, gm, p, p0i)
	for i := range nn {
		w := modPMontyMul(t5[i], r2, p, p0i)
		t2[i] = modPMontyMul(w, Fp[i], p, p0i)
		t3[i] = modPMontyMul(w, t4[i], p, p0i)
	}

	t4[0] = modPSet(g[0], p)
	t5[0] = t4[0]
	for i := 1; i < nn; i++ {
		t4[i] = modPSet(g[i], p)
		t5[nn-i] = modPSet(-g[i], p)
	}
	modPNTT2(t4, logN, gm, p, p0i)
	modPNTT2(t5, logN, gm, p, p0i)
	for i := range nn {
		w := modPMontyMul(t5[i], r2, p, p0i)
		t2[i] = modPAdd(t2[i], modPMontyMul(w, Gp[i], p, p0i), p)
		t3[i] = modPAdd(t3[i], modPMontyMul(w, t4[i], p, p0i), p)
	}

	modPINTT2(t2, logN, igm, p, p0i)
	modPINTT2(t3, logN, igm, p, p0i)

	num := fprs.take(nn)
	den := fprs.take(hn)
	work := fprs.take(nn)
	for i := range nn {
		work[i] = fpr(modPNorm(t3[i], p))
	}
	fftSlice(work, logN)
	copy(den, work[:hn])
	for i := range nn {
		num[i] = fpr(modPNorm(t2[i], p))
	}
	fftSlice(num, logN)
	fftDivAutoAdj(num, den, logN)
	inverseFFTSlice(num, logN)
	for i := range nn {
		t2[i] = modPSet(int32(fprRint(num[i])), p)
	}
	for i := range nn {
		t4[i] = modPSet(f[i], p)
		t5[i] = modPSet(g[i], p)
	}
	modPNTT2(t2, logN, gm, p, p0i)
	modPNTT2(t4, logN, gm, p, p0i)
	modPNTT2(t5, logN, gm, p, p0i)
	for i := range nn {
		kw := modPMontyMul(t2[i], r2, p, p0i)
		Fp[i] = modPSub(Fp[i], modPMontyMul(kw, t4[i], p, p0i), p)
		Gp[i] = modPSub(Gp[i], modPMontyMul(kw, t5[i], p, p0i), p)
	}
	modPINTT2(Fp, logN, igm, p, p0i)
	modPINTT2(Gp, logN, igm, p, p0i)
	for i := range nn {
		tmp[i] = uint32(modPNorm(Fp[i], p))
		tmp[nn+i] = uint32(modPNorm(Gp[i], p))
	}
	return true
}

func solveNTRUBinaryDepth1(f, g smallPolynomial, wk *ntruWorkspace) bool {
	depth := 1
	logn := logN - depth
	nn := 1 << logn
	hn := nn >> 1
	slen := maxBlSmall[depth]
	dlen := maxBlSmall[depth+1]
	llen := maxBlLarge[depth]

	tmp := wk.state
	u32s := newUint32Scratch(wk.scratch)
	fprs := newFPRScratch(wk.fpr)

	Fd := u32s.takeCopy(tmp[:dlen*hn])
	Gd := u32s.takeCopy(tmp[dlen*hn : 2*dlen*hn])
	Ft := u32s.take(nn * llen)
	Gt := u32s.take(nn * llen)
	ft := u32s.take(nn * slen)
	gt := u32s.take(nn * slen)
	gmFull := u32s.take(n)
	igmFull := u32s.take(n)
	fx := u32s.take(n)
	gx := u32s.take(n)
	Fp := u32s.take(hn)
	Gp := u32s.take(hn)
	crtScratch := u32s.take(max(llen, slen))
	for u := range llen {
		p := primes[u].p
		p0i := modPNInv31(p)
		r2 := modPR2(p, p0i)
		rx := modPRx(dlen, p, p0i, r2)
		for v := range hn {
			Ft[v*llen+u] = zintModSmallSigned(Fd[v*dlen:v*dlen+dlen], p, p0i, r2, rx)
			Gt[v*llen+u] = zintModSmallSigned(Gd[v*dlen:v*dlen+dlen], p, p0i, r2, rx)
		}
	}
	for u := range llen {
		p := primes[u].p
		p0i := modPNInv31(p)
		r2 := modPR2(p, p0i)

		modPMkgm2(gmFull, igmFull, logN, primes[u].g, p, p0i)
		for v := range n {
			fx[v] = modPSet(f[v], p)
			gx[v] = modPSet(g[v], p)
		}
		modPNTT2(fx, logN, gmFull, p, p0i)
		modPNTT2(gx, logN, gmFull, p, p0i)
		for e := logN; e > logn; e-- {
			modPPolyRecRes(fx, e, p, p0i, r2)
			modPPolyRecRes(gx, e, p, p0i, r2)
		}

		gm := gmFull[:nn]
		igm := igmFull[:nn]
		for v := range hn {
			Fp[v] = Ft[v*llen+u]
			Gp[v] = Gt[v*llen+u]
		}
		modPNTT2(Fp, logn-1, gm, p, p0i)
		modPNTT2(Gp, logn-1, gm, p, p0i)
		for v := range hn {
			ftA := fx[v<<1]
			ftB := fx[(v<<1)+1]
			gtA := gx[v<<1]
			gtB := gx[(v<<1)+1]
			mFp := modPMontyMul(Fp[v], r2, p, p0i)
			mGp := modPMontyMul(Gp[v], r2, p, p0i)
			Ft[(v<<1)*llen+u] = modPMontyMul(gtB, mFp, p, p0i)
			Ft[((v<<1)+1)*llen+u] = modPMontyMul(gtA, mFp, p, p0i)
			Gt[(v<<1)*llen+u] = modPMontyMul(ftB, mGp, p, p0i)
			Gt[((v<<1)+1)*llen+u] = modPMontyMul(ftA, mGp, p, p0i)
		}
		modPINTT2Ext(Ft[u:], llen, logn, igm, p, p0i)
		modPINTT2Ext(Gt[u:], llen, logn, igm, p, p0i)

		if u < slen {
			modPINTT2(fx[:nn], logn, igm, p, p0i)
			modPINTT2(gx[:nn], logn, igm, p, p0i)
			for v := range nn {
				ft[v*slen+u] = fx[v]
				gt[v*slen+u] = gx[v]
			}
		}
	}

	zintRebuildCRT(Ft, llen, llen, nn, primes[:], true, crtScratch[:llen])
	zintRebuildCRT(Gt, llen, llen, nn, primes[:], true, crtScratch[:llen])
	zintRebuildCRT(ft, slen, slen, nn, primes[:], true, crtScratch[:slen])
	zintRebuildCRT(gt, slen, slen, nn, primes[:], true, crtScratch[:slen])

	rt1 := fprs.take(nn)
	rt2 := fprs.take(nn)
	rt3 := fprs.take(nn)
	rt4 := fprs.take(nn)
	polyBigToFP(rt1, Ft, llen, llen, logn)
	polyBigToFP(rt2, Gt, llen, llen, logn)
	polyBigToFP(rt3, ft, slen, slen, logn)
	polyBigToFP(rt4, gt, slen, slen, logn)

	fftSlice(rt1, logn)
	fftSlice(rt2, logn)
	fftSlice(rt3, logn)
	fftSlice(rt4, logn)

	rt5 := fprs.take(nn)
	rt6 := fprs.take(nn >> 1)
	fftAddMulAdj(rt5, rt1, rt2, rt3, rt4, logn)
	fftInvNorm2(rt6, rt3, rt4, logn)
	fftMulAutoAdj(rt5, rt6, logn)

	inverseFFTSlice(rt5, logn)
	for i := range nn {
		z := rt5[i]
		if !(z < 9223372036854775807.0) || !(-9223372036854775807.0 < z) {
			return false
		}
		rt5[i] = fpr(fprRint(z))
	}
	fftSlice(rt5, logn)

	kf := fprs.take(nn)
	kg := fprs.take(nn)
	copy(kf, rt3)
	copy(kg, rt4)
	fftMulSlice(kf, rt5, logn)
	fftMulSlice(kg, rt5, logn)
	fftSub(rt1, kf, logn)
	fftSub(rt2, kg, logn)
	inverseFFTSlice(rt1, logn)
	inverseFFTSlice(rt2, logn)
	for i := range nn {
		tmp[i] = uint32(fprRint(rt1[i]))
		tmp[nn+i] = uint32(fprRint(rt2[i]))
	}
	return true
}
