package falcon1024

import (
	"crypto/sha3"
	"errors"
)

const (
	n                  = 1024
	q                  = 12289
	qNegInv            = 12287 // -q^-1 mod 2^16
	r2                 = 10952 // 2^32 mod q
	nInverseMontgomery = 64    // n^-1 * 2^16 mod q
	modQBits           = 14
	modQEncodedSize    = (n*modQBits + 7) >> 3
)

type fieldElement uint32

func fieldFromSmall(x int32) fieldElement {
	y := uint32(x)
	y += q & -(y >> 31)
	return fieldElement(y)
}

func fieldReduceOnce(a uint32) fieldElement {
	x := a - q
	x += q & -(x >> 31)
	return fieldElement(x)
}

func fieldAdd(a, b fieldElement) fieldElement {
	x := uint32(a + b)
	return fieldReduceOnce(x)
}

func fieldSub(a, b fieldElement) fieldElement {
	x := uint32(a - b + q)
	return fieldReduceOnce(x)
}

func fieldMontgomeryMul(a, b fieldElement) fieldElement {
	x := uint32(a) * uint32(b)
	return fieldMontgomeryReduce(x)
}

func fieldMontgomeryReduce(x uint32) fieldElement {
	w := ((x * qNegInv) & 0xFFFF) * q
	x = (x + w) >> 16
	x -= q
	x += q & -(x >> 31)
	return fieldElement(x)
}

func fieldMontgomeryMulSub(a, b, c fieldElement) fieldElement {
	x := uint32(a) * uint32(b-c+q)
	return fieldMontgomeryReduce(x)
}

func fieldCenteredMod(x fieldElement) int32 {
	v := int32(x)
	if v > int32(q/2) {
		v -= int32(q)
	}
	return v
}

const hashToPointRejectThreshold = 5 * q // 61445

type ringElement [n]fieldElement // modulo-q polynomial

func polyByteDecode[T ~[n]fieldElement](b []byte) (T, error) {
	if len(b) != modQEncodedSize {
		return T{}, errors.New("falcon-1024: invalid encoding length")
	}

	var p T
	for i := 0; i < n; i += 4 {
		x := uint64(b[0])<<48 |
			uint64(b[1])<<40 |
			uint64(b[2])<<32 |
			uint64(b[3])<<24 |
			uint64(b[4])<<16 |
			uint64(b[5])<<8 |
			uint64(b[6])

		p[i+0] = fieldElement((x >> 42) & 0x3FFF)
		p[i+1] = fieldElement((x >> 28) & 0x3FFF)
		p[i+2] = fieldElement((x >> 14) & 0x3FFF)
		p[i+3] = fieldElement(x & 0x3FFF)

		if p[i+0] >= q || p[i+1] >= q || p[i+2] >= q || p[i+3] >= q {
			return T{}, errors.New("falcon-1024: invalid polynomial encoding")
		}

		b = b[7:]
	}

	return p, nil
}

func hashToPoint(h *sha3.SHAKE) (ringElement, error) {
	var p ringElement
	var buf [2]byte

	for i := 0; i < n; {
		if _, err := h.Read(buf[:]); err != nil {
			return ringElement{}, err
		}

		w := uint32(buf[0])<<8 | uint32(buf[1])
		if w >= hashToPointRejectThreshold {
			continue
		}

		p[i] = fieldElement(w % q)
		i++
	}

	return p, nil
}

func polyAdd[T ~[n]fieldElement](a, b T) (s T) {
	for i := range s {
		s[i] = fieldAdd(a[i], b[i])
	}
	return s
}

func polySub[T ~[n]fieldElement](a, b T) (s T) {
	for i := range s {
		s[i] = fieldSub(a[i], b[i])
	}
	return s
}

type nttElement [n]fieldElement // NTT-domain modulo-q polynomial

func ntt(f ringElement) nttElement {
	t := n
	for m := 1; m < n; m <<= 1 {
		ht := t >> 1
		for i, j1 := 0, 0; i < m; i, j1 = i+1, j1+t {
			s := gmb[m+i]
			j2 := j1 + ht
			for j := j1; j < j2; j++ {
				u := f[j]
				v := fieldMontgomeryMul(f[j+ht], s)
				f[j] = fieldAdd(u, v)
				f[j+ht] = fieldSub(u, v)
			}
		}
		t = ht
	}
	return nttElement(f)
}

func inverseNTT(f nttElement) ringElement {
	t := 1
	m := n
	for m > 1 {
		hm := m >> 1
		dt := t << 1
		for i, j1 := 0, 0; i < hm; i, j1 = i+1, j1+dt {
			j2 := j1 + t
			s := igmb[hm+i]
			for j := j1; j < j2; j++ {
				u := f[j]
				v := f[j+t]
				f[j] = fieldAdd(u, v)
				w := fieldSub(u, v)
				f[j+t] = fieldMontgomeryMul(w, s)
			}
		}
		t = dt
		m = hm
	}

	for i := range f {
		f[i] = fieldMontgomeryMul(f[i], nInverseMontgomery)
	}
	return ringElement(f)
}

func nttMul(a, b nttElement) (p nttElement) {
	for i := range p {
		p[i] = fieldMontgomeryMul(a[i], b[i])
	}
	return p
}

func toNTTMonty(h ringElement) nttElement {
	hm := ntt(h)
	for i := range hm {
		hm[i] = fieldMontgomeryMul(hm[i], r2)
	}
	return hm
}

const signatureNormBound uint64 = 70_265_242

type smallPolynomial [n]int32 // signed small coefficients

func signatureNormWithinBound(s1, s2 smallPolynomial) bool {
	var norm uint64

	for i := range s1 {
		x := int64(s1[i])
		norm += uint64(x * x)

		y := int64(s2[i])
		norm += uint64(y * y)

		if norm > signatureNormBound {
			return false
		}
	}

	return true
}
