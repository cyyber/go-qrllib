package mlkem1024

import (
	"bytes"
	"math/big"
	"strconv"
	"testing"
)

func TestFieldReduce(t *testing.T) {
	for a := range uint32(2 * q * q) {
		got := fieldReduce(a)
		exp := fieldElement(a % q)
		if got != exp {
			t.Fatalf("reduce(%d) = %d, expected %d", a, got, exp)
		}
	}
}

func TestFieldReduceWide(t *testing.T) {
	const maxNTTMulAdd4Lazy = 4*2*(q-1)*(q-1) + (q - 1)
	for _, x := range []uint32{
		0, 1, q - 1, q, q + 1, 2*q - 1, 2 * q,
		maxNTTMulAdd4Lazy - 1, maxNTTMulAdd4Lazy,
	} {
		if got, want := fieldReduceWide(x), fieldElement(x%q); got != want {
			t.Fatalf("fieldReduceWide(%d) = %d, want %d", x, got, want)
		}
	}

	for x := uint32(0); x < maxNTTMulAdd4Lazy; x += 7919 {
		if got, want := fieldReduceWide(x), fieldElement(x%q); got != want {
			t.Fatalf("fieldReduceWide(%d) = %d, want %d", x, got, want)
		}
	}
}

func TestFieldAdd(t *testing.T) {
	for a := range fieldElement(q) {
		for b := range fieldElement(q) {
			got := fieldAdd(a, b)
			exp := (a + b) % q
			if got != exp {
				t.Fatalf("%d + %d = %d, expected %d", a, b, got, exp)
			}
		}
	}
}

func TestFieldSub(t *testing.T) {
	for a := range fieldElement(q) {
		for b := range fieldElement(q) {
			got := fieldSub(a, b)
			exp := (a - b + q) % q
			if got != exp {
				t.Fatalf("%d - %d = %d, expected %d", a, b, got, exp)
			}
		}
	}
}

func TestFieldMul(t *testing.T) {
	for a := range fieldElement(q) {
		for b := range fieldElement(q) {
			got := fieldMul(a, b)
			exp := fieldElement((uint32(a) * uint32(b)) % q)
			if got != exp {
				t.Fatalf("%d * %d = %d, expected %d", a, b, got, exp)
			}
		}
	}
}

func TestDecompressCompress(t *testing.T) {
	for _, d := range []uint8{d1, d5, d11} {
		for y := uint16(0); y < 1<<d; y++ {
			f := decompress(y, d)
			if f >= q {
				t.Fatalf("decompress(%d, %d) = %d >= q", y, d, f)
			}
			got := compressByBits(f, d)
			if got != y {
				t.Fatalf("compress(decompress(%d, %d), %d) = %d", y, d, d, got)
			}
		}

		maxDiff := fieldElement(q / (1 << d))
		for x := range fieldElement(q) {
			c := compressByBits(x, d)
			if c >= 1<<d {
				t.Fatalf("compress(%d, %d) = %d >= 2^d", x, d, c)
			}
			got := decompress(c, d)
			diff := fieldDistance(x, got)
			if diff > maxDiff {
				t.Fatalf("decompress(compress(%d, %d), %d) = %d (diff %d, max diff %d)",
					x, d, d, got, diff, maxDiff)
			}
		}
	}
}

func fieldDistance(a, b fieldElement) fieldElement {
	if a > b {
		return min(a-b, b+q-a)
	}
	return min(b-a, a+q-b)
}

func TestCompressMatchesRat(t *testing.T) {
	for _, d := range []uint8{d1, d5, d11} {
		for x := range fieldElement(q) {
			got := compressByBits(x, d)
			want := compressRat(x, d)
			if got != want {
				t.Fatalf("compress(%d, %d) = %d, want %d", x, d, got, want)
			}
		}
	}
}

func TestDecompressMatchesRat(t *testing.T) {
	for _, d := range []uint8{d1, d5, d11} {
		limit := uint16(1) << d
		for y := range limit {
			got := decompress(y, d)
			want := decompressRat(y, d)
			if got != want {
				t.Fatalf("decompress(%d, %d) = %d, want %d", y, d, got, want)
			}
		}
	}
}

func compressRat(x fieldElement, d uint8) uint16 {
	if x >= q {
		panic("x out of range")
	}
	if d == 0 || d >= 12 {
		panic("d out of range")
	}

	scale := int64(1) << d
	precise := big.NewRat(scale*int64(x), int64(q))
	rounded, err := strconv.ParseInt(precise.FloatString(0), 10, 64)
	if err != nil {
		panic(err)
	}
	return uint16(rounded % scale)
}

func decompressRat(y uint16, d uint8) fieldElement {
	if d == 0 || d >= 12 {
		panic("d out of range")
	}
	scale := int64(1) << d
	if int64(y) >= scale {
		panic("y out of range")
	}

	precise := big.NewRat(int64(q)*int64(y), scale)
	rounded, err := strconv.ParseInt(precise.FloatString(0), 10, 64)
	if err != nil {
		panic(err)
	}
	return fieldElement(rounded % int64(q))
}

func TestRingEncodeDecode(t *testing.T) {
	var f ringElement
	for i := range f {
		f[i] = fieldElement((11*i*i + 19*i + 5) % q)
	}

	var b [encodingSize11]byte
	for i := range b {
		b[i] = byte(37*i + 11)
	}

	for _, tc := range []struct {
		d    uint8
		size int
	}{
		{d1, encodingSize1},
		{d5, encodingSize5},
		{d11, encodingSize11},
	} {
		got := ringCompressAndEncodeSpecialized(&f, tc.d)
		want := ringCompressAndEncodeByBits(&f, tc.d)
		if !bytes.Equal(got, want) {
			t.Fatalf("ringCompressAndEncode specialized d=%d mismatch", tc.d)
		}

		g1 := ringDecodeAndDecompressByBits(b[:tc.size], tc.d)
		g2 := ringDecodeAndDecompressSpecialized(b[:tc.size], tc.d)
		if g1 != g2 {
			t.Fatalf("ringDecodeAndDecompress specialized d=%d mismatch", tc.d)
		}

		out := ringCompressAndEncodeSpecialized(&g2, tc.d)
		if !bytes.Equal(out, b[:tc.size]) {
			t.Fatalf("ringCompressAndEncode/ringDecodeAndDecompress round trip failed for d=%d", tc.d)
		}
	}
}

func ringCompressAndEncodeByBits(src *ringElement, d uint8) []byte {
	dst := make([]byte, int(d)*n/8)
	for i, x := range src {
		c := compressByBits(x, d)
		for j := uint8(0); j < d; j++ {
			bitOffset := i*int(d) + int(j)
			dst[bitOffset/8] |= byte(c>>j&1) << (bitOffset % 8)
		}
	}
	return dst
}

func ringCompressAndEncodeSpecialized(src *ringElement, d uint8) []byte {
	switch d {
	case d1:
		var dst [encodingSize1]byte
		ringCompressAndEncode1(&dst, src)
		return dst[:]
	case d5:
		var dst [encodingSize5]byte
		ringCompressAndEncode5(&dst, src)
		return dst[:]
	case d11:
		var dst [encodingSize11]byte
		ringCompressAndEncode11(&dst, src)
		return dst[:]
	default:
		panic("unsupported compression width")
	}
}

func ringDecodeAndDecompressByBits(src []byte, d uint8) ringElement {
	var dst ringElement
	for i := range dst {
		var acc uint16
		for j := range d {
			bitOffset := i*int(d) + int(j)
			bit := src[bitOffset/8] >> (bitOffset % 8) & 1
			acc |= uint16(bit) << j
		}
		dst[i] = decompress(acc, d)
	}
	return dst
}

func ringDecodeAndDecompressSpecialized(src []byte, d uint8) ringElement {
	var dst ringElement
	switch d {
	case d1:
		ringDecodeAndDecompress1(&dst, (*[encodingSize1]byte)(src[:encodingSize1]))
	case d5:
		ringDecodeAndDecompress5(&dst, (*[encodingSize5]byte)(src[:encodingSize5]))
	case d11:
		ringDecodeAndDecompress11(&dst, (*[encodingSize11]byte)(src[:encodingSize11]))
	default:
		panic("unsupported compression width")
	}
	return dst
}

func compressByBits(x fieldElement, d uint8) uint16 {
	switch d {
	case d1:
		return uint16(compress1(x))
	case d5:
		return compress5(x)
	case d11:
		return compress11(x)
	default:
		panic("unsupported compression width")
	}
}
