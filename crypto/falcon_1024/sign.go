package falcon

import "golang.org/x/crypto/sha3"

func smallIntsToFPR(dst fprPoly, src coeffPoly) {
	for i := range polyDegree {
		dst[i] = fprOf(src[i])
	}
}

func ffSamplingFFTDynTree(
	rng sha3.ShakeHash,
	t0, t1 fprPoly,
	g00, g01, g11 fprPoly,
	origLogn, logn int,
) error {
	return nil
}

func doSignDyn(rng sha3.ShakeHash, f, g, ntruF, ntruG, hm coeffPoly) (coeffPoly, bool) {
	// 1. Build basis B0 = [[g, -f], [G, -F]] in FFT.
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

	// 2. Build Gram matrix without destroying B0.
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

	// 3. Compute target coordinates.
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

	// 4. Sample around target using dynamic LDL tree.
	// This function must mutate tx, ty into sampled coordinates.
	if err := ffSamplingFFTDynTree(rng, t0, t1, g00, g01, g11, logPolyDegree, logPolyDegree); err != nil {
		return nil, false
	}

	// 5. Map back through B0 to get signature vector.
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

func signDyn(rng sha3.ShakeHash, f, g, ntruF, ntruG, hm coeffPoly) (coeffPoly, error) {
	for {
		if sigp, ok := doSignDyn(rng, f, g, ntruF, ntruG, hm); ok {
			return sigp, nil
		}
	}
}
