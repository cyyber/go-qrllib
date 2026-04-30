package falcon1024

import (
	"errors"
	"strconv"
)

const (
	seedSize       = 48
	publicKeySize  = 1793
	privateKeySize = 2305
	signatureSize  = 1280
)

type PrivateKey struct {
	seed [seedSize]byte
	pub  *PublicKey
	// pub  [publicKeySize]byte
	// TODO
}

func (priv *PrivateKey) Bytes() []byte {
	k := make([]byte, 0, privateKeySize)
	// k = append(k, priv.seed[:]...)
	// k = append(k, priv.pub[:]...)
	return k
}

func (priv *PrivateKey) Seed() []byte {
	seed := priv.seed
	return seed[:]
}

func (priv *PrivateKey) PublicKey() *PublicKey {
	// pub := priv.pub
	// return pub[:]
	return nil
}

type PublicKey struct {
	// TODO
}

func (pub *PublicKey) Bytes() []byte {
	// TODO
	// a := pub.aBytes
	// return a[:]
	return nil
}

// GenerateKey generates a new Falcon-1024 private key pair.
func GenerateKey() (*PrivateKey, error) {
	return nil, nil
}

func generateKey(priv *PrivateKey) (*PrivateKey, error) {
	precomputePrivateKey(priv)
	return nil, nil
}

func NewPrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	priv := &PrivateKey{}
	return newPrivateKeyFromSeed(priv, seed)
}

func newPrivateKeyFromSeed(priv *PrivateKey, seed []byte) (*PrivateKey, error) {
	if l := len(seed); l != seedSize {
		return nil, errors.New("ed25519: bad seed length: " + strconv.Itoa(l))
	}
	copy(priv.seed[:], seed)
	precomputePrivateKey(priv)
	return priv, nil
}

func precomputePrivateKey(priv *PrivateKey) {}

func NewPrivateKey(priv []byte) (*PrivateKey, error) {
	p := &PrivateKey{}
	return newPrivateKey(p, priv)
}

func newPrivateKey(priv *PrivateKey, privBytes []byte) (*PrivateKey, error) {
	// TODO
	return nil, nil
}

func NewPublicKey(pub []byte) (*PublicKey, error) {
	p := &PublicKey{}
	return newPublicKey(p, pub)
}

func newPublicKey(pub *PublicKey, pubBytes []byte) (*PublicKey, error) {
	/*
		if l := len(pubBytes); l != publicKeySize {
			return nil, errors.New("ed25519: bad public key length: " + strconv.Itoa(l))
		}
		// SetBytes checks that the point is on the curve.
		if _, err := pub.a.SetBytes(pubBytes); err != nil {
			return nil, errors.New("ed25519: bad public key")
		}
		copy(pub.aBytes[:], pubBytes)
		return pub, nil
	*/
	return nil, nil
}

func Sign(priv *PrivateKey, message []byte) []byte {
	return nil
}

func sign(signature []byte, priv *PrivateKey, message []byte) []byte {
	return nil
}

func Verify(pub *PublicKey, message, sig []byte) error {
	return nil
}

func verify(pub *PublicKey, message, sig []byte) error {
	return nil
}
