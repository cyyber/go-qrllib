package mldsa87

import "github.com/theQRL/go-qrllib/crypto/internal/lattice"

func ntt(a *[N]int32) {
	lattice.NTT(a)
}

func invNTTToMont(a *[N]int32) {
	lattice.InvNTTToMont(a)
}

func montgomeryReduce(a int64) int32 {
	return lattice.MontgomeryReduce(a)
}

func reduce32(a int32) int32 {
	return lattice.Reduce32(a)
}

func cAddQ(a int32) int32 {
	return lattice.CAddQ(a)
}

func power2Round(a0 *int32, a int32) int32 {
	return lattice.Power2Round(a0, a)
}

func decompose(a0 *int32, a int32) int32 {
	return lattice.Decompose(a0, a)
}

func makeHint(a0, a1 int32) uint {
	return lattice.MakeHint(a0, a1)
}

func useHint(a int32, hint int) int32 {
	return lattice.UseHint(a, hint)
}
