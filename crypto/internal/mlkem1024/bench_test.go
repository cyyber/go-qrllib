package mlkem1024

import "testing"

var internalBenchmarkSink byte

func BenchmarkPKEEncrypt(b *testing.B) {
	var d, z [32]byte
	for i := range d {
		d[i] = byte(i)
		z[i] = byte(255 - i)
	}
	dk := GenerateKeyInternal(&d, &z)

	var m, r [32]byte
	for i := range m {
		m[i] = byte(3*i + 1)
		r[i] = byte(5*i + 7)
	}

	b.ReportAllocs()
	for b.Loop() {
		var ct [CiphertextSize]byte
		pkeEncrypt(&ct, &dk.encryptionKey, &m, r[:])
		internalBenchmarkSink ^= ct[0]
	}
}

func BenchmarkExpandMatrix(b *testing.B) {
	var rho [32]byte
	for i := range rho {
		rho[i] = byte(7*i + 3)
	}

	var a [k * k]ringElement

	b.ReportAllocs()
	for b.Loop() {
		for i := range k {
			for j := range k {
				sampleNTT(&a[i*k+j], &rho, byte(j), byte(i))
			}
		}
		internalBenchmarkSink ^= byte(a[k*k-1][n-1])
	}
}

func BenchmarkNTTMulAdd4(b *testing.B) {
	var a, c [4]ringElement
	for j := range 4 {
		for i := range n {
			a[j][i] = fieldElement((17*i*i + 31*i + 43*j + 7) % q)
			c[j][i] = fieldElement((23*i*i + 19*i + 29*j + 11) % q)
		}
	}

	b.Run("scalar4", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var acc ringElement
			nttMulAdd(&acc, &a[0], &c[0])
			nttMulAdd(&acc, &a[1], &c[1])
			nttMulAdd(&acc, &a[2], &c[2])
			nttMulAdd(&acc, &a[3], &c[3])
			internalBenchmarkSink ^= byte(acc[n-1])
		}
	})

	b.Run("fused4", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var acc ringElement
			nttMulAdd4(&acc,
				&a[0], &c[0],
				&a[1], &c[1],
				&a[2], &c[2],
				&a[3], &c[3],
			)
			internalBenchmarkSink ^= byte(acc[n-1])
		}
	})
}
