package mlkem1024

import (
	"crypto/rand"
	"crypto/sha3"
	"io"
)

const (
	k = 4
)

type DecapsulationKey struct {
	d, z [32]byte
}

func (dk *DecapsulationKey) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	// TODO
	return nil, nil
}

func (dk *DecapsulationKey) EncapsulationKey() *EncapsulationKey {
	// TODO
	return nil
}

func (dk *DecapsulationKey) Bytes() []byte {
	// TODO
	return nil
}

type EncapsulationKey struct{}

func (ek *EncapsulationKey) Encapsulate() (sharedKey, ciphertext []byte) {
	// TODO
	return nil, nil
}

func (ek *EncapsulationKey) encapsulate() (sharedKey, ciphertext []byte) {
	// TODO
	return nil, nil
}

func (ek *EncapsulationKey) Bytes() []byte {
	// TODO
	return nil
}

func GenerateKey() (*DecapsulationKey, error) {
	dk := &DecapsulationKey{}
	return generateKey(dk)
}

func generateKey(dk *DecapsulationKey) (*DecapsulationKey, error) {
	var d, z [32]byte
	if _, err := io.ReadFull(rand.Reader, d[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, z[:]); err != nil {
		return nil, err
	}
	keygen(dk, &d, &z)
	return dk, nil
}

func keygen(dk *DecapsulationKey, d *[32]byte, z *[32]byte) *DecapsulationKey {
	dk.d = *d
	dk.z = *z

	g := sha3.New256()
	_, _ = g.Write(d[:])
	_, _ = g.Write([]byte{k})
	G := g.Sum(make([]byte, 0, 64))
	ρ, σ := G[:32], G[32:]

	a := [k * k]ringElement{}

	for i := range byte(k) {
		for j := range byte(k) {
			a[i*k+j] = sampleNTT(ρ, j, i)
		}
	}

	var N byte
	s := [k]ringElement{}
	for i := range s {
		s[i] = samplePolyCBD(σ, N)
		// ntt()
		N++
	}
	e := [k]ringElement{}
	for i := range e {
		e[i] = samplePolyCBD(σ, N)
		// ntt()
		N++
	}

	// TODO
	// ekPKE ← ByteEncode12(𝐭)‖�
	// dkPKE ← ByteEncode12(𝐬)

	return dk
}
