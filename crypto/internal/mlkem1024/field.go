package mlkem1024

import "crypto/sha3"

const (
	// n is the ML-KEM-1024 polynomial degree.
	n = 256
	// q is the ML-KEM-1024 field modulus.
	q = 3329
)

type fieldElement uint32

type ringElement [n]fieldElement // modulo-q polynomial

// TODO nttElement?

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

func samplePolyCBD(σ []byte, N byte) ringElement {
	// TODO
	return ringElement{}
}

func ntt(f []fieldElement) {
	// TODO
}

func inverseNTT(f []fieldElement) {
	// TODO
}

func nttMul(a, b []fieldElement) {
	// TODO
}
