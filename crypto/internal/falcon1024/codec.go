package falcon1024

import "errors"

const maxCompressedCoefficient = 2047

type compressedBitReader struct {
	src     []byte
	pos     int
	current byte
	bits    int
}

func (r *compressedBitReader) readBit() (uint32, bool) {
	if r.bits == 0 {
		if r.pos >= len(r.src) {
			return 0, false
		}
		r.current = r.src[r.pos]
		r.pos++
		r.bits = 8
	}

	r.bits--
	return uint32(r.current>>r.bits) & 1, true
}

func (r *compressedBitReader) readBits(n int) (uint32, bool) {
	var v uint32
	for range n {
		bit, ok := r.readBit()
		if !ok {
			return 0, false
		}
		v = (v << 1) | bit
	}
	return v, true
}

func (r *compressedBitReader) trailingBitsAreZero() bool {
	if r.bits == 0 {
		return true
	}
	return r.current&byte((1<<r.bits)-1) == 0
}

var (
	errInvalidSignatureEncoding = errors.New("falcon-1024: invalid signature encoding")
)

func compressedDecode(src []byte) (smallPolynomial, int, error) {
	var p smallPolynomial
	r := compressedBitReader{src: src}

	for i := range p {
		b, ok := r.readBits(8)
		if !ok {
			return smallPolynomial{}, 0, errInvalidSignatureEncoding
		}

		negative := b&0x80 != 0
		magnitude := int32(b & 0x7f)

		for {
			bit, ok := r.readBit()
			if !ok {
				return smallPolynomial{}, 0, errInvalidSignatureEncoding
			}
			if bit == 1 {
				break
			}

			magnitude += 128
			if magnitude > maxCompressedCoefficient {
				return smallPolynomial{}, 0, errInvalidSignatureEncoding
			}
		}

		if negative {
			if magnitude == 0 {
				return smallPolynomial{}, 0, errInvalidSignatureEncoding
			}
			magnitude = -magnitude
		}

		p[i] = magnitude
	}

	if !r.trailingBitsAreZero() {
		return smallPolynomial{}, 0, errInvalidSignatureEncoding
	}

	return p, r.pos, nil
}
