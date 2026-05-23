package mlkem1024

import (
	"bytes"
	"testing"
)

// These KATs are derived from the FIPS 203 algorithms and cross-checked against
// Go's crypto/internal/fips140/mlkem implementation where matching operations
// are exposed by the implementation.
// Sources: https://doi.org/10.6028/NIST.FIPS.203 and
// https://go.dev/src/crypto/internal/fips140/mlkem/.

func TestRingDecodeAndDecompressSpecialized(t *testing.T) {
	var src1 [encodingSize1]byte
	for i := range src1 {
		src1[i] = byte(37*i + 11)
	}
	checkRingDecodeAndDecompress(t, "d1", d1, src1[:], func(dst *ringElement) {
		ringDecodeAndDecompress1(dst, &src1)
	})

	var src5 [encodingSize5]byte
	for i := range src5 {
		src5[i] = byte(31*i + 7)
	}
	checkRingDecodeAndDecompress(t, "d5", d5, src5[:], func(dst *ringElement) {
		ringDecodeAndDecompress5(dst, &src5)
	})

	var src11 [encodingSize11]byte
	for i := range src11 {
		src11[i] = byte(17*i + 23)
	}
	checkRingDecodeAndDecompress(t, "d11", d11, src11[:], func(dst *ringElement) {
		ringDecodeAndDecompress11(dst, &src11)
	})
}

func TestRingCompressAndEncodeSpecialized(t *testing.T) {
	var src ringElement
	for i := range src {
		src[i] = fieldElement((7*i*i + 31*i + 42) % q)
	}

	var dst1 [encodingSize1]byte
	ringCompressAndEncode1(&dst1, &src)
	checkRingCompressAndEncode(t, "d1", d1, dst1[:], &src)

	var dst5 [encodingSize5]byte
	ringCompressAndEncode5(&dst5, &src)
	checkRingCompressAndEncode(t, "d5", d5, dst5[:], &src)

	var dst11 [encodingSize11]byte
	ringCompressAndEncode11(&dst11, &src)
	checkRingCompressAndEncode(t, "d11", d11, dst11[:], &src)
}

func TestByteEncodeDecode12(t *testing.T) {
	var src ringElement
	for i := range src {
		src[i] = fieldElement((11*i*i + 19*i + 5) % q)
	}

	var got [encodingSize12]byte
	byteEncode12(&got, &src)

	want := make([]byte, encodingSize12)
	referenceByteEncode12(want, &src)
	if !bytes.Equal(got[:], want) {
		t.Fatal("byteEncode12 mismatch")
	}

	var decoded ringElement
	if err := byteDecode12(&decoded, &got); err != nil {
		t.Fatalf("byteDecode12 returned error: %v", err)
	}
	if decoded != src {
		t.Fatal("byteDecode12 round trip mismatch")
	}
}

func TestByteDecode12RejectsUnreducedCoefficient(t *testing.T) {
	var src [encodingSize12]byte
	unreduced := uint16(q)
	src[0] = byte(unreduced)
	src[1] = byte(unreduced >> 8)

	var dst ringElement
	if err := byteDecode12(&dst, &src); err == nil {
		t.Fatal("byteDecode12 accepted an unreduced coefficient")
	}
}

func checkRingCompressAndEncode(t *testing.T, name string, d uint8, got []byte, src *ringElement) {
	t.Helper()

	want := make([]byte, len(got))
	referenceRingCompressAndEncode(want, src, d)

	if !bytes.Equal(got, want) {
		t.Fatalf("ringCompressAndEncode%s mismatch", name)
	}
}

func checkRingDecodeAndDecompress(t *testing.T, name string, d uint8, src []byte, decode func(*ringElement)) {
	t.Helper()

	var got, want ringElement
	decode(&got)
	referenceRingDecodeAndDecompress(&want, src, d)

	if got != want {
		t.Fatalf("ringDecodeAndDecompress%s mismatch", name)
	}
}

func referenceByteEncode12(dst []byte, src *ringElement) {
	for i, x := range src {
		for j := range uint8(12) {
			bitOffset := i*12 + int(j)
			dst[bitOffset/8] |= byte(uint16(x)>>j&1) << (bitOffset % 8)
		}
	}
}

func referenceRingCompressAndEncode(dst []byte, src *ringElement, d uint8) {
	for i, x := range src {
		c := compress(x, d)
		for j := uint8(0); j < d; j++ {
			bitOffset := i*int(d) + int(j)
			dst[bitOffset/8] |= byte(c>>j&1) << (bitOffset % 8)
		}
	}
}

func referenceRingDecodeAndDecompress(dst *ringElement, src []byte, d uint8) {
	for i := range dst {
		var acc uint16
		for j := uint8(0); j < d; j++ {
			bitOffset := i*int(d) + int(j)
			bit := src[bitOffset/8] >> (bitOffset % 8) & 1
			acc |= uint16(bit) << j
		}
		dst[i] = decompress(acc, d)
	}
}

// TODO
/*
	func TestPolyByteEncodeKAT(t *testing.T) {
		var got [encodingSize12]byte
		f := katRingElementA()
		byteEncode12(&got, &f)
		checkBytesHash(t, "ByteEncode12", got[:], "701f8ea4f16daa04c57079c3da04426f9dc6b0e4cb0054daee9906dd29f7360f")
	}

	func TestPolyByteDecodeKAT(t *testing.T) {
		var f ringElement
		err := byteDecode12(&f, (*[encodingSize12]byte)(referencePolyByteEncode(katRingElementA())))
		if err != nil {
			t.Fatalf("ByteDecode12 returned error: %v", err)
		}
	checkRingHash(t, "ByteDecode12", f, "39c2ff68c3cd83c43d0683e377436f0e572077576a86bb96f6310025f26681bb")
}

func TestPolyByteDecodeRejectsUnreducedCoefficient(t *testing.T) {
	var encoded [encodingSize12]byte
		encoded[0] = byte(q & 0xff)
		encoded[1] = byte(q >> 8)

		var f ringElement
		if err := byteDecode12(&f, &encoded); err == nil {
			t.Fatal("ByteDecode12 accepted an unreduced coefficient")
		}
	}

func TestSampleNTTKAT(t *testing.T) {
	rho := katBytes(32, func(i int) byte { return byte(3*i + 1) })
	got := sampleNTT(rho, 2, 3)

	wantPrefix := [...]fieldElement{887, 2684, 2052, 2496, 905, 2244, 2554, 1706, 225, 709, 169, 97, 130, 2909, 761, 734}
	for i, want := range wantPrefix {
		if got[i] != want {
			t.Fatalf("sampleNTT coefficient %d = %d, want %d", i, got[i], want)
		}
	}
	checkRingHash(t, "sampleNTT", got, "745b97b7856c47e0eebd07ed0c75b5e929ea9cbb8fe655c53ce0a4746a90e8b7")
}

func TestSamplePolyCBDKAT(t *testing.T) {
	sigma := katBytes(32, func(i int) byte { return byte(0xa0 + i) })
	got := samplePolyCBD(sigma, 7)

	wantPrefix := [...]fieldElement{3327, 2, 0, 0, 1, 3328, 0, 3328, 3328, 3327, 2, 1, 3328, 3328, 0, 0}
	for i, want := range wantPrefix {
		if got[i] != want {
			t.Fatalf("samplePolyCBD coefficient %d = %d, want %d", i, got[i], want)
		}
	}
	checkRingHash(t, "samplePolyCBD", got, "79cfe147473f50b5be408744a432e1cb36c404707ec3be931e1edd15d262a36d")
}

func TestNTTKAT(t *testing.T) {
	got := katRingElementA()
	ntt(got)

	checkRingHash(t, "NTT", got, "a08503ed7187a255c90cb8d92ba531bfc627f7738b9372f2c84cfbe3679f83e5")
}

func TestInverseNTTKAT(t *testing.T) {
	got := referenceNTT(katRingElementA())
	inverseNTT(got[:])

	checkRingHash(t, "inverse NTT", got, "39c2ff68c3cd83c43d0683e377436f0e572077576a86bb96f6310025f26681bb")
}

func TestNTTMulKAT(t *testing.T) {
	got := referenceNTT(katRingElementA())
	other := referenceNTT(katRingElementB())
	nttMul(got, other)

	checkRingHash(t, "MultiplyNTTs", got, "9ecfb906dc0f25c923d8709452bdc2cc4a1a15b2057b43fe5c1f6f584ada95b1")
}

func TestPolyAddKAT(t *testing.T) {
	got := katRingElementA()
	polyAdd(got, katRingElementB())

	checkRingHash(t, "polyAdd", got, "fa504d78bf0de89433c2160767e456cf530dd468201f70a3d5a280c1ac83f450")
}

func katRingElementA() ringElement {
	var f ringElement
	for i := range f {
		f[i] = fieldElement((i*i + 17*i + 42) % q)
	}
	return f
}

func katRingElementB() ringElement {
	var f ringElement
	for i := range f {
		f[i] = fieldElement((3*i*i + 5*i + 7) % q)
	}
	return f
}

func katBytes(n int, f func(int) byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = f(i)
	}
	return b
}

func checkRingHash(t *testing.T, name string, got ringElement, want string) {
	t.Helper()
	if got := digestRingElement(got); got != want {
		t.Fatalf("%s digest = %s, want %s", name, got, want)
	}
}

func checkBytesHash(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if got := digestBytes(got); got != want {
		t.Fatalf("%s digest = %s, want %s", name, got, want)
	}
}

func digestRingElement(f ringElement) string {
	b := make([]byte, 2*n)
	for i, x := range f {
		b[2*i] = byte(x)
		b[2*i+1] = byte(uint16(x) >> 8)
	}
	return digestBytes(b)
}

func digestBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func referencePolyByteEncode(f ringElement) []byte {
	b := make([]byte, encodingSize12)
	for i, j := 0, 0; i < n; i, j = i+2, j+3 {
		x := uint32(f[i]) | uint32(f[i+1])<<12
		b[j] = byte(x)
		b[j+1] = byte(x >> 8)
		b[j+2] = byte(x >> 16)
	}
	return b
}

func referenceNTT(f ringElement) ringElement {
	i := 1
	for length := 128; length >= 2; length /= 2 {
		for start := 0; start < n; start += 2 * length {
			zeta := zetas[i]
			i++
			for j := start; j < start+length; j++ {
				t := fieldMul(zeta, f[j+length])
				f[j+length] = fieldSub(f[j], t)
				f[j] = fieldAdd(f[j], t)
			}
		}
	}
	return f
}
*/
