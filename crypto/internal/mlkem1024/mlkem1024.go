package mlkem1024

import (
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"errors"
	"io"
)

const (
	k = 4

	encodingSize11 = n * 11 / 8
	encodingSize5  = n * 5 / 8
	encodingSize12 = n * 12 / 8

	ciphertextSize       = k*encodingSize11 + encodingSize5
	sharedKeySize        = 32
	seedSize             = 64
	encapsulationKeySize = 1568
)

type DecapsulationKey struct {
	d, z [32]byte
	h    [32]byte // H(ekPKE)
	encryptionKey
	decryptionKey
}

func NewDecapsulationKey(seed []byte) (*DecapsulationKey, error) {
	if len(seed) != seedSize {
		return nil, errors.New("ml-kem-1024: invalid seed length")
	}
	dk := &DecapsulationKey{}
	d := (*[32]byte)(seed[:32])
	z := (*[32]byte)(seed[32:])
	return generateKey(dk, d, z), nil
}

func (dk *DecapsulationKey) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	if len(ciphertext) != ciphertextSize {
		return nil, errors.New("ml-kem-1024: invalid ciphertext length")
	}
	return decapsulate(dk, (*[ciphertextSize]byte)(ciphertext)), nil
}

func decapsulate(dk *DecapsulationKey, ct *[ciphertextSize]byte) (sharedKey []byte) {
	m := pkeDecrypt(dk, ct)

	g := sha3.New512()
	_, _ = g.Write(m[:])
	_, _ = g.Write(dk.h[:])
	G := g.Sum(make([]byte, 0, 64))
	K, r := G[:sharedKeySize], G[sharedKeySize:]

	J := sha3.NewSHAKE256()
	_, _ = J.Write(dk.z[:])
	_, _ = J.Write(ct[:])
	Kout := make([]byte, sharedKeySize)
	_, _ = J.Read(Kout)

	c := pkeEncrypt(ct, dk.EncapsulationKey(), &m, r)

	subtle.ConstantTimeCopy(subtle.ConstantTimeCompare(ct[:], c), Kout, K)

	return Kout
}

func (dk *DecapsulationKey) EncapsulationKey() *EncapsulationKey {
	return &EncapsulationKey{
		h:             dk.h,
		encryptionKey: dk.encryptionKey,
	}
}

func (dk *DecapsulationKey) Bytes() []byte {
	var b [seedSize]byte
	copy(b[:], dk.d[:])
	copy(b[32:], dk.z[:])
	return b[:]
}

type EncapsulationKey struct {
	h [32]byte // H(ek)
	encryptionKey
}

func NewEncapsulationKey(ekPKE []byte) (*EncapsulationKey, error) {
	if len(ekPKE) != encapsulationKeySize {
		return nil, errors.New("ml-kem-1024: invalid encapsulation key length")
	}

	ek := &EncapsulationKey{}

	// TODO
	// h := sha3.New256()
	// _, _ = h.Write(ekPKE)
	// h.Sum(ek.h[:0])

	// var err error
	// for i := range ek.t {
	// 	// ek.t[i], err = polyByteDecode(ekPKE[:encodingSize12])
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	ekPKE = ekPKE[encodingSize12:]
	// }

	return ek, nil
}

func (ek *EncapsulationKey) Encapsulate() (sharedKey, ciphertext []byte, err error) {
	var m [32]byte
	if _, err := io.ReadFull(rand.Reader, m[:]); err != nil {
		return nil, nil, err
	}
	var ct [ciphertextSize]byte
	K, c := encapsulate(&ct, ek, &m)
	return K, c, nil
}

func encapsulate(ct *[ciphertextSize]byte, ek *EncapsulationKey, m *[32]byte) (K []byte, c []byte) {
	g := sha3.New512()
	_, _ = g.Write(m[:])
	_, _ = g.Write(ek.h[:])
	G := g.Sum(nil)
	K, r := G[:sharedKeySize], G[sharedKeySize:]

	c = pkeEncrypt(ct, ek, m, r)

	return K, c
}

func (ek *EncapsulationKey) Bytes() []byte {
	b := make([]byte, 0, encapsulationKeySize)
	var encoded [encodingSize12]byte
	for i := range ek.t {
		// TODO
		// polyByteEncode(encoded[:], ek.t[i])
		_ = i
		b = append(b, encoded[:]...)
	}

	// TODO calc a

	return b
}

type encryptionKey struct {
	t [k]fieldElement
	a [k * k]fieldElement
}

type decryptionKey struct {
	s [k]fieldElement
}

func GenerateKey() (*DecapsulationKey, error) {
	var d, z [32]byte
	if _, err := io.ReadFull(rand.Reader, d[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, z[:]); err != nil {
		return nil, err
	}
	dk := &DecapsulationKey{}
	return generateKey(dk, &d, &z), nil
}

func generateKey(dk *DecapsulationKey, d, z *[32]byte) *DecapsulationKey {
	dk.d, dk.z = *d, *z

	// TODO
	// g := sha3.New256()
	// _, _ = g.Write(dk.d[:])
	// _, _ = g.Write([]byte{k})
	// G := g.Sum(make([]byte, 0, 64))
	// ρ, σ := G[:32], G[32:]x

	return dk
}

func kemKeyGen(dk *DecapsulationKey, d *[32]byte, z *[32]byte) *DecapsulationKey {
	dk.d, dk.z = *d, *z

	// TODO
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

func pkeEncrypt(c *[ciphertextSize]byte, ek *EncapsulationKey, m *[32]byte, r []byte) []byte {
	// a := [k * k]ringElement{}
	// for i := range byte(k) {
	// 	for j := range byte(k) {
	// 		// TODO arg
	// 		a[i*k+j] = sampleNTT(nil, j, i)
	// 	}
	// }

	// var N byte
	// var y ringElement
	// for i := range k {
	// 	y[i] = samplePolyCBD(r, N)
	// 	N++
	// }
	// for i := range k {
	// 	y[i] = samplePolyCBD(r, N)
	// 	N++
	// }
	// e2 := samplePolyCBD(r, N)
	// ntt(y)
	// inverseNTT()

	return nil
}

func pkeDecrypt(dk *DecapsulationKey, c *[ciphertextSize]byte) [32]byte {
	// TODO
	return [32]byte{}
}
