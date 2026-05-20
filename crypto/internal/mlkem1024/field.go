package mlkem1024

import "crypto/sha3"

const (
	// n is the ML-KEM-1024 polynomial degree.
	n = 256
	// q is the ML-KEM-1024 field modulus.
	q = 3329
)

type fieldElement uint16

func fieldReduceOnce(a uint16) fieldElement {
	x := a - q
	x += q & -(x >> 15)
	return fieldElement(x)
}

func fieldAdd(a, b fieldElement) fieldElement {
	x := uint16(a + b)
	return fieldReduceOnce(x)
}

func fieldSub(a, b fieldElement) fieldElement {
	x := uint16(a - b + q)
	return fieldReduceOnce(x)
}

const (
	barrettMultiplier = 5039
	barrettShift      = 24
)

// fieldReduce reduces a value a < 2q² using Barrett reduction, to avoid
// potentially variable-time division.
func fieldReduce(a uint32) fieldElement {
	quotient := uint32((uint64(a) * barrettMultiplier) >> barrettShift)
	return fieldReduceOnce(uint16(a - quotient*q))
}

func fieldMul(a, b fieldElement) fieldElement {
	x := uint32(a) * uint32(b)
	return fieldReduce(x)
}

type ringElement [n]fieldElement // modulo-q polynomial

func sampleNTT(ρ []byte, jj, ii byte) ringElement {
	ctx := sha3.NewSHAKE128()
	_, _ = ctx.Write(ρ)
	_, _ = ctx.Write([]byte{jj, ii})

	var a ringElement
	var j int
	var buf [168]byte
	off := len(buf)

	for {
		if off >= len(buf) {
			ctx.Read(buf[:])
			off = 0
		}

		d1 := uint16(buf[off]) | (uint16(buf[off+1]&0x0f) << 8)
		d2 := uint16(buf[off+1]>>4) | (uint16(buf[off+2]) << 4)
		off += 3

		if d1 < q {
			a[j] = fieldElement(d1)
			j++
		}
		if j >= len(a) {
			break
		}
		if d2 < q {
			a[j] = fieldElement(d2)
			j++
		}
		if j >= len(a) {
			break
		}
	}

	return a
}

func polyByteEncode[T ~[n]fieldElement](dst []byte, p T) {
	// TODO
}

func samplePolyCBD(σ []byte, N byte) ringElement {
	prf := sha3.NewSHAKE256()
	_, _ = prf.Write(σ)
	_, _ = prf.Write([]byte{N})
	B := make([]byte, 64*2)
	_, _ = prf.Read(B)

	// TODO
	// var f ringElement
	// for i := 0; i < 256; i++ {
	// 	f[i] = fieldSub(x, y)
	// }

	return ringElement{}
}

var zetas = [128]fieldElement{1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154}

func ntt(f ringElement) {
	i := 1
	for length := 128; length >= 2; length /= 2 {
		for start := 0; start < 256; start += 2 * length {
			zeta := zetas[i]
			i++
			for j := start; j < start+length; j++ {
				t := fieldMul(zeta, f[j+length])
				f[j+length] = fieldSub(f[j], t)
				f[j] = fieldAdd(f[j], t)
			}
		}
	}
}

var gammas = [128]fieldElement{17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229, 1409, 1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279, 1703, 1626, 1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642, 939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688, 1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684, 1063, 2266, 319, 3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735, 2804, 525, 1092, 2237, 403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443, 1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175}

func nttMul(a, b ringElement) {
	for i := 0; i < 128; i++ {
		c0 := fieldAdd(fieldMul(a[2*i], b[2*i]), fieldMul(fieldMul(a[2*i+1], b[2*i+1]), gammas[i]))
		c1 := fieldAdd(fieldMul(a[2*i], b[2*i+1]), fieldMul(a[2*i+1], b[2*i]))
		a[2*i] = c0
		a[2*i+1] = c1
	}
}

func inverseNTT(f []fieldElement) {
	i := 127
	for length := 2; length <= 128; length *= 2 {
		for start := 0; start < 256; start += 2 * length {
			zeta := zetas[i]
			i--
			for j := start; j < start+length; j++ {
				t := f[j]
				f[j] = fieldAdd(t, f[j+length])
				f[j+length] = fieldMul(zeta, fieldSub(f[j+length], t))
			}
		}
	}
	for i := range f {
		f[i] = fieldMul(f[i], 3303)
	}
}

func polyAdd(a, b ringElement) {
	// TODO
}
