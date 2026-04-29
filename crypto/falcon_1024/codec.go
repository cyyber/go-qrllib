package falcon

import "errors"

const (
	maxCompMagnitude = 2047
)

var (
	ErrCompEncodeCoefficientOutOfRange = errors.New("signature coefficient exceeds supported compressed range")
	ErrCompEncodeDestinationTooSmall   = errors.New("compressed signature buffer too small")
)

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
	// TODO
	return 0, nil
}

func trimI8Decode(src []byte, bits int) (coeffPoly, int, error) {
	// TODO
	return nil, 0, nil
}
