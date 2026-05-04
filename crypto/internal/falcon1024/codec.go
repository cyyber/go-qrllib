package falcon1024

import "errors"

const (
	maxCompressedCoefficient = 2047
	modQBits                 = 14
	modQEncodedSize          = (n*modQBits + 7) >> 3
)

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

var errInvalidSignatureEncoding = errors.New("falcon-1024: invalid signature encoding")

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

func compressedEncode(dst []byte, s smallPolynomial) (int, error) {
	// TODO
	return 0, nil
}

func skEncode(dst []byte, f, g, ntruF smallPolynomial) error {
	// TODO
	return nil
}

func skDecode(src []byte) (f, g, ntruF smallPolynomial, err error) {
	// TODO
	return smallPolynomial{}, smallPolynomial{}, smallPolynomial{}, nil
}

func pkEncode(dst []byte, h ringElement) error {
	// TODO
	return nil
}

func pkDecode(src []byte) (h ringElement, err error) {
	return polyByteDecode[ringElement](src[encodedHeaderSize:])
}

func sigEncode(dst []byte, nonce *[nonceSize]byte, s2 smallPolynomial) error {
	dst[0] = signatureHeader
	copy(dst[encodedHeaderSize:signaturePrefixSize], nonce[:])

	written, err := compressedEncode(dst[signaturePrefixSize:], s2)
	if err != nil {
		return err
	}
	clear(dst[signaturePrefixSize+written:])

	return nil
}

func sigDecode(src []byte) (nonce [nonceSize]byte, s2 smallPolynomial, err error) {
	copy(nonce[:], src[encodedHeaderSize:signaturePrefixSize])

	s2, consumed, err := compressedDecode(src[signaturePrefixSize:])
	if err != nil {
		return nonce, smallPolynomial{}, err
	}

	for _, b := range src[signaturePrefixSize+consumed:] {
		if b != 0 {
			return nonce, smallPolynomial{}, errors.New("falcon-1024: invalid signature")
		}
	}

	return nonce, s2, nil
}
