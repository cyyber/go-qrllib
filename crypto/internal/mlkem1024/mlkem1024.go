package mlkem1024

import (
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"errors"
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

	SharedKeySize = 32
	SeedSize      = 32 + 32

	// ML-KEM-1024 parameters.
	k = 4

	CiphertextSize       = k*encodingSize11 + encodingSize5
	EncapsulationKeySize = k*encodingSize12 + 32
)

type DecapsulationKey struct {
	d, z [32]byte // decapsulation key seeds
	h    [32]byte // H(ekPKE)
	encryptionKey
	decryptionKey
}

func NewDecapsulationKey(seed []byte) (*DecapsulationKey, error) {
	if len(seed) != SeedSize {
		return nil, errors.New("ml-kem-1024: invalid seed length")
	}

	dk := &DecapsulationKey{}
	d := (*[32]byte)(seed[:32])
	z := (*[32]byte)(seed[32:])

	generateKey(dk, d, z)

	return dk, nil
}

func (dk *DecapsulationKey) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	if len(ciphertext) != CiphertextSize {
		return nil, errors.New("ml-kem-1024: invalid ciphertext length")
	}

	return decapsulate(dk, (*[CiphertextSize]byte)(ciphertext)), nil
}

func decapsulate(dk *DecapsulationKey, ct *[CiphertextSize]byte) (sharedKey []byte) {
	var m [messageSize]byte

	pkeDecrypt(&m, dk, ct)

	g := sha3.New512()
	_, _ = g.Write(m[:])
	_, _ = g.Write(dk.h[:])
	G := g.Sum(make([]byte, 0, 64))
	K, r := G[:SharedKeySize], G[SharedKeySize:]

	J := sha3.NewSHAKE256()
	_, _ = J.Write(dk.z[:])
	_, _ = J.Write(ct[:])
	Kout := make([]byte, SharedKeySize)
	_, _ = J.Read(Kout)

	var c [CiphertextSize]byte
	pkeEncrypt(&c, &dk.encryptionKey, &m, r)

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
	var b [SeedSize]byte
	copy(b[:], dk.d[:])
	copy(b[32:], dk.z[:])

	return b[:]
}

type EncapsulationKey struct {
	h [32]byte // H(ek)
	encryptionKey
}

func NewEncapsulationKey(ekBytes []byte) (*EncapsulationKey, error) {
	if len(ekBytes) != EncapsulationKeySize {
		return nil, errors.New("ml-kem-1024: invalid encapsulation key length")
	}

	ek := &EncapsulationKey{}

	H := sha3.New256()
	_, _ = H.Write(ekBytes)
	H.Sum(ek.h[:0])

	var err error
	for i := range ek.t {
		err = byteDecode12(&ek.t[i], (*[encodingSize12]byte)(ekBytes[:encodingSize12]))
		if err != nil {
			return nil, err
		}
		ekBytes = ekBytes[encodingSize12:]
	}
	copy(ek.rho[:], ekBytes)

	for i := range k {
		for j := range k {
			sampleNTT(&ek.a[i*k+j], &ek.rho, byte(j), byte(i))
		}
	}

	return ek, nil
}

func (ek *EncapsulationKey) Encapsulate() (sharedKey, ciphertext []byte, err error) {
	var m [32]byte
	_, _ = rand.Read(m[:])

	var ct [CiphertextSize]byte
	sharedKey = encapsulateTo(&ct, ek, &m)

	return sharedKey, ct[:], nil
}

func encapsulateTo(dst *[CiphertextSize]byte, ek *EncapsulationKey, m *[32]byte) []byte {
	g := sha3.New512()
	_, _ = g.Write(m[:])
	_, _ = g.Write(ek.h[:])
	G := g.Sum(nil)
	K, r := G[:SharedKeySize], G[SharedKeySize:]

	pkeEncrypt(dst, &ek.encryptionKey, m, r)

	return K
}

func (ek *EncapsulationKey) Bytes() []byte {
	b := new([EncapsulationKeySize]byte)
	ek.encryptionKey.encode(b)

	return b[:]
}

func (ek *encryptionKey) encode(dst *[EncapsulationKeySize]byte) {
	off := 0
	for i := range ek.t {
		byteEncode12((*[encodingSize12]byte)(dst[off:off+encodingSize12]), &ek.t[i])
		off += encodingSize12
	}
	copy(dst[off:], ek.rho[:])
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
	_, _ = rand.Read(d[:])
	_, _ = rand.Read(z[:])
	dk := &DecapsulationKey{}

	generateKey(dk, &d, &z)

	return dk, nil
}

func generateKey(dk *DecapsulationKey, d, z *[32]byte) {
	dk.d, dk.z = *d, *z

	pkeKeyGen(dk, d)

	var ekBytes [EncapsulationKeySize]byte
	dk.encryptionKey.encode(&ekBytes)

	H := sha3.New256()
	_, _ = H.Write(ekBytes[:])
	H.Sum(dk.h[:0])
}

// GenerateKeyInternal is a derandomized version of GenerateKey,
// exclusively for use in tests.
func GenerateKeyInternal(d, z *[32]byte) *DecapsulationKey {
	dk := &DecapsulationKey{}
	generateKey(dk, d, z)
	return dk
}
