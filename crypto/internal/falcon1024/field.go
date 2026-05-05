package falcon1024

import (
	"crypto/sha3"
	"errors"
)

const (
	n                  = 1024
	logN               = 10
	q                  = 12289
	qNegInv            = 12287 // -q^-1 mod 2^16
	r2                 = 10952 // 2^32 mod q
	nInverseMontgomery = 64    // n^-1 * 2^16 mod q
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

// fieldInv returns 1/x mod q. x must be non-zero.
func fieldInv(x fieldElement) fieldElement {
	return fieldMontgomeryMul(fieldInvMontgomery(x), 1)
}

// fieldDiv returns x/y mod q. y must be non-zero.
func fieldDiv(x, y fieldElement) fieldElement {
	return fieldMontgomeryMul(x, fieldInvMontgomery(y))
}

// fieldInvMontgomery returns 1/x in Montgomery representation.
func fieldInvMontgomery(x fieldElement) fieldElement {
	y0 := fieldMontgomeryMul(x, r2)
	y1 := fieldMontgomerySqr(y0)
	y2 := fieldMontgomeryMul(y1, y0)
	y3 := fieldMontgomeryMul(y2, y1)
	y4 := fieldMontgomerySqr(y3)
	y5 := fieldMontgomerySqr(y4)
	y6 := fieldMontgomerySqr(y5)
	y7 := fieldMontgomerySqr(y6)
	y8 := fieldMontgomerySqr(y7)
	y9 := fieldMontgomeryMul(y8, y2)
	y10 := fieldMontgomeryMul(y9, y8)
	y11 := fieldMontgomerySqr(y10)
	y12 := fieldMontgomerySqr(y11)
	y13 := fieldMontgomeryMul(y12, y9)
	y14 := fieldMontgomerySqr(y13)
	y15 := fieldMontgomerySqr(y14)
	y16 := fieldMontgomeryMul(y15, y10)
	y17 := fieldMontgomerySqr(y16)
	return fieldMontgomeryMul(y17, y0)
}

func fieldMontgomerySqr(x fieldElement) fieldElement {
	return fieldMontgomeryMul(x, x)
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

func polyByteEncode[T ~[n]fieldElement](dst []byte, p T) {
	for i := 0; i < n; i += 4 {
		x := uint64(p[i+0])<<42 |
			uint64(p[i+1])<<28 |
			uint64(p[i+2])<<14 |
			uint64(p[i+3])

		dst[0] = byte(x >> 48)
		dst[1] = byte(x >> 40)
		dst[2] = byte(x >> 32)
		dst[3] = byte(x >> 24)
		dst[4] = byte(x >> 16)
		dst[5] = byte(x >> 8)
		dst[6] = byte(x)

		dst = dst[7:]
	}
}

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

type smallPolynomial [n]int32

func sampleSmallPolynomial(rng *sha3.SHAKE) smallPolynomial {
	// TODO
	return smallPolynomial{}
}

func coefficientsExceedBound(p smallPolynomial, bound int32) bool {
	for _, x := range p {
		if x < -bound || x > bound {
			return true
		}
	}
	return false
}

func squaredNormExceedsBound(f, g smallPolynomial, bound uint32) bool {
	// TODO
	return f.squaredNorm()+g.squaredNorm() > bound
}

func orthogonalizedNormExceedsBound(f, g smallPolynomial, bound float64) bool {
	// TODO
	return false
}

func signatureNormExceedsPartialBound(sqn uint32, s2 smallPolynomial) bool {
	// TODO
	return false
}

func (p smallPolynomial) squaredNorm() uint32 {
	var n uint32
	for _, x := range p {
		n += uint32(x * x)
	}
	return n
}

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
