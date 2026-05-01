package falcon_1024

import "errors"

const (
	maxCompMagnitude = 2047
	modQBits         = 14
	modQEncodedSize  = (polyDegree * modQBits) >> 3
)

var (
	ErrCompEncodeCoefficientOutOfRange   = errors.New("signature coefficient exceeds supported compressed range")
	ErrCompEncodeDestinationTooSmall     = errors.New("compressed signature buffer too small")
	ErrTrimI8EncodeCoefficientOutOfRange = errors.New("private key coefficient exceeds supported trimmed range")
	ErrTrimI8EncodeDestinationTooSmall   = errors.New("trimmed private key buffer too small")
	ErrModQEncodeWrongCoefficientCount   = errors.New("mod q polynomial has wrong coefficient count")
	ErrModQEncodeCoefficientOutOfRange   = errors.New("mod q coefficient out of range")
	ErrModQEncodeDestinationTooSmall     = errors.New("mod q buffer too small")
	ErrModQDecodeInputTooShort           = errors.New("mod q input too short")
	ErrModQDecodeCoefficientOutOfRange   = errors.New("mod q coefficient out of range")
	ErrModQDecodeTrailingBits            = errors.New("mod q trailing bits are not zero")
)

func modQEncode(dst []byte, h mqPoly) (int, error) {
	if len(h) != polyDegree {
		return 0, ErrModQEncodeWrongCoefficientCount
	}
	if len(dst) < modQEncodedSize {
		return 0, ErrModQEncodeDestinationTooSmall
	}

	var acc uint32
	accLen := 0
	written := 0

	for _, x := range h {
		if x >= modulusQ {
			return 0, ErrModQEncodeCoefficientOutOfRange
		}

		acc = (acc << modQBits) | x
		accLen += modQBits

		for accLen >= 8 {
			accLen -= 8
			dst[written] = byte(acc >> accLen)
			written++
		}
	}

	if accLen > 0 {
		dst[written] = byte(acc << (8 - accLen))
		written++
	}

	return written, nil
}

func modQDecode(src []byte) (mqPoly, int, error) {
	if len(src) < modQEncodedSize {
		return nil, 0, ErrModQDecodeInputTooShort
	}

	h := newMQPoly()

	var acc uint32
	accLen := 0
	read := 0

	for i := range polyDegree {
		for accLen < modQBits {
			acc = (acc << 8) | uint32(src[read])
			read++
			accLen += 8
		}

		accLen -= modQBits
		x := (acc >> accLen) & ((1 << modQBits) - 1)
		if x >= modulusQ {
			return nil, 0, ErrModQDecodeCoefficientOutOfRange
		}

		h[i] = x
	}

	if read != modQEncodedSize {
		return nil, 0, ErrModQDecodeInputTooShort
	}

	if accLen > 0 && (acc&((1<<accLen)-1)) != 0 {
		return nil, 0, ErrModQDecodeTrailingBits
	}

	return h, read, nil
}

func compEncode(dst []byte, p coeffPoly) (int, error) {
	for _, xi := range p {
		if xi < -maxCompMagnitude || xi > maxCompMagnitude {
			return 0, ErrCompEncodeCoefficientOutOfRange
		}
	}

	var acc uint32
	accLen := 0
	written := 0

	for _, xi := range p {
		acc <<= 1

		t := xi
		if t < 0 {
			t = -t
			acc |= 1
		}

		w := uint32(t)
		acc = (acc << 7) | (w & 127)
		w >>= 7
		accLen += 8

		acc = (acc << (w + 1)) | 1
		accLen += int(w) + 1

		for accLen >= 8 {
			accLen -= 8
			if written >= len(dst) {
				return 0, ErrCompEncodeDestinationTooSmall
			}
			dst[written] = byte(acc >> accLen)
			written++
		}
	}

	if accLen > 0 {
		if written >= len(dst) {
			return 0, ErrCompEncodeDestinationTooSmall
		}
		dst[written] = byte(acc << (8 - accLen))
		written++
	}

	return written, nil
}

func trimI8Encode(dst []byte, x coeffPoly, bits int) (int, error) {
	required := (len(x)*bits + 7) >> 3
	if len(dst) < required {
		return 0, ErrTrimI8EncodeDestinationTooSmall
	}

	maxValue := int32((1 << (bits - 1)) - 1)
	minValue := -maxValue

	if bits == 8 {
		for i, xi := range x {
			if xi < minValue || xi > maxValue {
				return 0, ErrTrimI8EncodeCoefficientOutOfRange
			}
			dst[i] = byte(int8(xi))
		}
		return required, nil
	}

	mask := uint32((1 << bits) - 1)
	var acc uint32
	accLen := 0
	written := 0

	for _, xi := range x {
		if xi < minValue || xi > maxValue {
			return 0, ErrTrimI8EncodeCoefficientOutOfRange
		}

		acc = (acc << bits) | (uint32(xi) & mask)
		accLen += bits
		if accLen >= 8 {
			accLen -= 8
			dst[written] = byte(acc >> accLen)
			written++
		}
	}

	if accLen > 0 {
		dst[written] = byte(acc << (8 - accLen))
		written++
	}

	return written, nil
}

func trimI8Decode(src []byte, bits int) (coeffPoly, int, error) {
	if bits < 2 || bits > 8 {
		return nil, 0, ErrInvalidPrivateKeyFormat
	}

	required := (polyDegree*bits + 7) >> 3
	if len(src) < required {
		return nil, 0, ErrInvalidPrivateKeyFormat
	}

	p := newCoeffPoly()

	if bits == 8 {
		for i := range polyDegree {
			v := int8(src[i])
			if v == -128 {
				return nil, 0, ErrInvalidPrivateKeyFormat
			}
			p[i] = int32(v)
		}
		return p, required, nil
	}

	mask := uint32((1 << bits) - 1)
	signBit := int32(1 << (bits - 1))
	fullRange := int32(1 << bits)
	var acc uint32
	accLen := 0
	read := 0

	for i := range polyDegree {
		for accLen < bits {
			acc = (acc << 8) | uint32(src[read])
			read++
			accLen += 8
		}

		accLen -= bits
		v := int32((acc >> accLen) & mask)
		if v >= signBit {
			if v == signBit {
				return nil, 0, ErrInvalidPrivateKeyFormat
			}
			v -= fullRange
		}
		p[i] = v

		if accLen == 0 {
			acc = 0
		} else {
			acc &= (1 << accLen) - 1
		}
	}

	if acc != 0 {
		return nil, 0, ErrInvalidPrivateKeyFormat
	}

	return p, required, nil
}
