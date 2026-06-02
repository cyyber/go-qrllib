package mlkem1024

import (
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

func fieldDistance(a, b fieldElement) fieldElement {
	if a > b {
		return min(a-b, b+q-a)
	}
	return min(b-a, a+q-b)
}
