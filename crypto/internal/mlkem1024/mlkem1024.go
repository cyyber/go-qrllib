package mlkem1024

import (
	"crypto/rand"
	"crypto/sha3"
	"io"
)

const (
	k              = 4
	encodingSize11 = n * 11 / 8
	encodingSize5  = n * 5 / 8
	ciphertextSize = k*encodingSize11 + encodingSize5
	sharedKeySize  = 32
)

type DecapsulationKey struct {
	d, z [32]byte

	encryptionKey
	decryptionKey
}

func (dk *DecapsulationKey) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	kemDecaps(dk, ciphertext)
	return nil, nil
}

func kemDecaps(dk *DecapsulationKey, ciphertext []byte) (K []byte) {
	// TODO
	// m := pkeDecrypt(dk, ciphertext)
	// g := sha3.New512()
	// _, _ = g.Write(m[:])
	// _, _ = g.Write(dk.h[:])
	// G := g.Sum(make([]byte, 0, 64))
	// Kprime, r := G[:sharedKeySize], G[sharedKeySize:]
	// J := sha3.New256()
	// _, _ = J.Write(dk.z[:])
	// _, _ = J.Write(c[:])
	// Kout := make([]byte, sharedKeySize)
	// J.Read(Kout)

	// c := pkeEncrypt(dk.ek, m, r)
	// if !bytes.Equal(ciphertext, c) {
	// 	K = K2
	// }

	// return k
	return nil
}

func (dk *DecapsulationKey) EncapsulationKey() *EncapsulationKey {
	// TODO
	return nil
}

func (dk *DecapsulationKey) Bytes() []byte {
	// TODO
	return nil
}

type EncapsulationKey struct {
	h [32]byte // H(ek)
}

func (ek *EncapsulationKey) Encapsulate() (sharedKey, ciphertext []byte, err error) {
	var ct [ciphertextSize]byte
	return ek.encapsulate(ct)
}

func (ek *EncapsulationKey) encapsulate(ct [ciphertextSize]byte) (sharedKey, ciphertext []byte, err error) {
	var m [32]byte
	if _, err := io.ReadFull(rand.Reader, m[:]); err != nil {
		return nil, nil, err
	}
	K, c := kemEncaps(ct, ek, &m)
	return K, c, nil
}

func kemEncaps(ct [ciphertextSize]byte, ek *EncapsulationKey, m *[32]byte) (K []byte, c []byte) {
	g := sha3.New256()
	_, _ = g.Write(m[:])
	_, _ = g.Write(ek.h[:])
	G := g.Sum(nil)
	K, r := G[:sharedKeySize], G[sharedKeySize:]
	c = pkeEncrypt(ct, ek, m, r)
	return K, c
}

func (ek *EncapsulationKey) Bytes() []byte {
	// TODO
	return nil
}

type encryptionKey struct{}

type decryptionKey struct{}

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
	kemKeyGen(dk, &d, &z)
	return dk, nil
}

func kemKeyGen(dk *DecapsulationKey, d *[32]byte, z *[32]byte) *DecapsulationKey {
	// TODO
	// dk.d = *d
	// dk.z = *z

	// g := sha3.New256()
	// _, _ = g.Write(d[:])
	// _, _ = g.Write([]byte{k})
	// G := g.Sum(make([]byte, 0, 64))
	// ρ, σ := G[:32], G[32:]

	// a := [k * k]ringElement{}

	// for i := range byte(k) {
	// 	for j := range byte(k) {
	// 		a[i*k+j] = sampleNTT(ρ, j, i)
	// 	}
	// }

	// var N byte
	// s := [k]ringElement{}
	// for i := range s {
	// 	s[i] = samplePolyCBD(σ, N)
	// 	// ntt()
	// 	N++
	// }
	// e := [k]ringElement{}
	// for i := range e {
	// 	e[i] = samplePolyCBD(σ, N)
	// 	// ntt()
	// 	N++
	// }

	// ekPKE ← ByteEncode12(𝐭)‖�
	// dkPKE ← ByteEncode12(𝐬)

	return dk
}

func pkeEncrypt(ct [ciphertextSize]byte, ek *EncapsulationKey, m *[32]byte, r []byte) []byte {
	// TODO
	return nil
}

func pkeDecrypt(ek *EncapsulationKey, ct [ciphertextSize]byte) []byte {
	// TODO
	return nil
}
