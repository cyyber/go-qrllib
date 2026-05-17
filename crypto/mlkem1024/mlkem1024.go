package mlkem1024

import "github.com/theQRL/go-qrllib/crypto/internal/mlkem1024"

type DecapsulationKey struct {
	key *mlkem1024.DecapsulationKey
}

type EncapsulationKey struct {
	key *mlkem1024.EncapsulationKey
}

func GenerateKey() (*DecapsulationKey, error) {
	key, err := mlkem1024.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey{key}, nil
}
