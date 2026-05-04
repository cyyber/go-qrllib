package falcon1024

type fpr float64

type fprPolynomial [n]fpr

func fprFromSmall(dst *fprPolynomial, src smallPolynomial) {
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
}

type fprTree [(logN + 1) * n]fpr

type fftPolynomial [n]fpr

func fft(f *fprPolynomial) fftPolynomial {
	// TODO
	return fftPolynomial{}
}

func inverseFFT(fftPolynomial) fprPolynomial {
	// TODO
	return fprPolynomial{}
}

func polyNeg[T ~[n]fpr](p *T) {
	for i := range *p {
		(*p)[i] = -(*p)[i]
	}
}
