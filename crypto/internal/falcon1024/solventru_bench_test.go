package falcon1024

import (
	"encoding/hex"
	"testing"
)

func benchSolveNTRUInputs(b *testing.B) (smallPolynomial, smallPolynomial) {
	b.Helper()
	rawF, err := hex.DecodeString(ntru_f_1024Hex)
	if err != nil {
		b.Fatal(err)
	}
	rawG, err := hex.DecodeString(ntru_g_1024Hex)
	if err != nil {
		b.Fatal(err)
	}
	var f, g smallPolynomial
	for i := range f {
		f[i] = int32(int8(rawF[i]))
		g[i] = int32(int8(rawG[i]))
	}
	return f, g
}

func BenchmarkSolveNTRU(b *testing.B) {
	f, g := benchSolveNTRUInputs(b)
	b.ResetTimer()
	for range b.N {
		_, _, ok := solveNTRU(f, g)
		if !ok {
			b.Fatal("solveNTRU returned !ok on reference inputs")
		}
	}
}
