package mlkem1024

import "crypto/sha3"

// K-PKE (FIPS 203, Section 5): the IND-CPA-secure public-key encryption
// scheme that ML-KEM wraps with the FO transform.

func pkeKeyGen(dk *DecapsulationKey, d *[32]byte) {
	g := sha3.New512()
	_, _ = g.Write(d[:])
	_, _ = g.Write([]byte{k})
	G := g.Sum(make([]byte, 0, 64))
	rho, sigma := G[:32], G[32:]
	copy(dk.rho[:], rho)

	A := &dk.a
	for i := range byte(k) {
		for j := range byte(k) {
			sampleNTT(&A[i*k+j], (*[32]byte)(rho), j, i)
		}
	}

	var N byte
	s := &dk.s
	for i := range s {
		samplePolyCBD(&s[i], sigma, N)
		ntt(&s[i])
		N++
	}

	e := make([]ringElement, k)
	for i := range e {
		samplePolyCBD(&e[i], sigma, N)
		ntt(&e[i])
		N++
	}

	t := &dk.t
	for i := range t {
		var acc ringElement
		for j := range s {
			nttMulAdd(&acc, &A[i*k+j], &s[j])
		}
		polyAddAssign(&acc, &e[i])
		t[i] = acc
	}
}

func pkeEncrypt(dst *[ciphertextSize]byte, ek *EncapsulationKey, m *[32]byte, r []byte) {
	var y, e1 [k]ringElement

	var counter byte
	for i := range y {
		samplePolyCBD(&y[i], r, counter)
		ntt(&y[i])
		counter++
	}

	for i := range e1 {
		samplePolyCBD(&e1[i], r, counter)
		counter++
	}

	var e2 ringElement
	samplePolyCBD(&e2, r, counter)

	var u [k]ringElement
	var acc ringElement
	for i := range u {
		for j := 0; j < k; j++ {
			nttMulAdd(&acc, &ek.a[j*k+i], &y[j])
		}
		inverseNTT(&acc)
		polyAddAssign(&acc, &e1[i])
		u[i] = acc
	}

	var mu ringElement
	ringDecodeAndDecompress1(&mu, m)

	var v ringElement
	for i := 0; i < k; i++ {
		nttMulAdd(&v, &ek.t[i], &y[i])
	}
	inverseNTT(&v)
	polyAddAssign(&v, &e2)
	polyAddAssign(&v, &mu)

	off := 0
	for i := range u {
		ringCompressAndEncode11((*[encodingSize11]byte)(dst[off:off+encodingSize11]), &u[i])
		off += encodingSize11
	}
	ringCompressAndEncode5((*[encodingSize5]byte)(dst[off:off+encodingSize5]), &v)
}

func pkeDecrypt(dst *[32]byte, dk *DecapsulationKey, c *[ciphertextSize]byte) {
	var u [k]ringElement

	off := 0
	for i := range u {
		ringDecodeAndDecompress11(&u[i], (*[encodingSize11]byte)(c[off:off+encodingSize11]))
		off += encodingSize11
	}

	var v ringElement
	ringDecodeAndDecompress5(&v, (*[encodingSize5]byte)(c[off:off+encodingSize5]))

	var acc ringElement
	for i := range k {
		ntt(&u[i])
		nttMulAdd(&acc, &dk.s[i], &u[i])
	}
	inverseNTT(&acc)

	w := v
	polySubAssign(&w, &acc)
	ringCompressAndEncode1(dst, &w)
}
