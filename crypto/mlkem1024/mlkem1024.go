package mlkem1024

import "github.com/theQRL/go-qrllib/crypto/internal/mlkem1024"

type DecapsulationKey struct {
	key *mlkem1024.DecapsulationKey
}

func (dk *DecapsulationKey) Decapsulate(cyphertext []byte) (sharedKey []byte, err error) {
	// TODO
	return nil, nil
}

func (dk *DecapsulationKey) EncapsulationKey() *EncapsulationKey {
	// TODO
	return nil
}

func (dk *DecapsulationKey) Bytes() []byte {
	return dk.key.Bytes()
}

type EncapsulationKey struct {
	key *mlkem1024.EncapsulationKey
}

func (ek *EncapsulationKey) Encapsulate() (sharedkey, cyphertext []byte) {
	// TODO
	return nil, nil
}

func (ek *EncapsulationKey) Bytes() []byte {
	return ek.key.Bytes()
}

func GenerateKey() (*DecapsulationKey, error) {
	key, err := mlkem1024.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey{key}, nil
}
