package falcon1024

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
	// TODO
	return fftPolynomial{}, fftPolynomial{}, nil
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
