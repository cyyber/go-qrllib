package mlkem1024

import (
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"errors"
	"io"
)

const (
	// ML-KEM global constants.
	n = 256
	q = 3329

	// Byte lengths of ByteEncode_d(f) output (FIPS 203, Algorithm 5)
	encodingSize1  = n * 1 / 8
	encodingSize5  = n * 5 / 8
	encodingSize11 = n * 11 / 8
	encodingSize12 = n * 12 / 8

	messageSize = encodingSize1

	sharedKeySize = 32
	seedSize      = 32 + 32

	// ML-KEM-1024 parameters.
	k = 4

	ciphertextSize       = k*encodingSize11 + encodingSize5
	encapsulationKeySize = 1568
)

type DecapsulationKey struct {
	d, z [32]byte // decapsulation key seeds
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

	generateKey(dk, d, z)

	return dk, nil
}

func (dk *DecapsulationKey) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	if len(ciphertext) != ciphertextSize {
		return nil, errors.New("ml-kem-1024: invalid ciphertext length")
	}

	return decapsulate(dk, (*[ciphertextSize]byte)(ciphertext)), nil
}

func decapsulate(dk *DecapsulationKey, ct *[ciphertextSize]byte) (sharedKey []byte) {
	var m [messageSize]byte

	pkeDecrypt(&m, dk, ct)

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

	var c [ciphertextSize]byte
	pkeEncrypt(&c, dk.EncapsulationKey(), &m, r)

	subtle.ConstantTimeCopy(subtle.ConstantTimeCompare(ct[:], c[:]), Kout, K)

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

	H := sha3.New256()
	_, _ = H.Write(ekPKE)
	H.Sum(ek.h[:0])

	var err error
	for i := range ek.t {
		err = polyByteDecode(&ek.t[i], (*[encodingSize12]byte)(ekPKE[:encodingSize12]))
		if err != nil {
			return nil, err
		}
		ekPKE = ekPKE[encodingSize12:]
	}
	copy(ek.rho[:], ekPKE)

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

	pkeEncrypt(ct, ek, m, r)

	return K, c
}

func (ek *EncapsulationKey) Bytes() []byte {
	b := make([]byte, 0, encapsulationKeySize)
	var encoded [encodingSize12]byte
	for i := range ek.t {
		polyByteEncode(&encoded, &ek.t[i])
		b = append(b, encoded[:]...)
	}
	b = append(b, ek.rho[:]...)

	return b
}

type encryptionKey struct {
	t   [k]ringElement     // public key vector
	a   [k * k]ringElement // public matrix A
	rho [32]byte           // matrix seed
}

type decryptionKey struct {
	s [k]ringElement // secret key vector
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

	generateKey(dk, &d, &z)

	return dk, nil
}

func generateKey(dk *DecapsulationKey, d, z *[32]byte) {
	dk.d, dk.z = *d, *z

	pkeKeyGen(dk, d)

	H := sha3.New256()
	_, _ = H.Write(dk.EncapsulationKey().Bytes())
	H.Sum(dk.h[:0])
}
