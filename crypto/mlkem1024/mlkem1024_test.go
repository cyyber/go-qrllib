package mlkem1024_test

import (
	"bytes"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/mlkem1024"
)

func TestInvalidInputLengths(t *testing.T) {
	if _, err := mlkem1024.NewDecapsulationKey(make([]byte, mlkem1024.SeedSize-1)); err == nil {
		t.Fatal("NewDecapsulationKey accepted a short seed")
	}
	if _, err := mlkem1024.NewDecapsulationKey(make([]byte, mlkem1024.SeedSize+1)); err == nil {
		t.Fatal("NewDecapsulationKey accepted a long seed")
	}
	if _, err := mlkem1024.NewEncapsulationKey(make([]byte, mlkem1024.EncapsulationKeySize-1)); err == nil {
		t.Fatal("NewEncapsulationKey accepted a short encapsulation key")
	}
	if _, err := mlkem1024.NewEncapsulationKey(make([]byte, mlkem1024.EncapsulationKeySize+1)); err == nil {
		t.Fatal("NewEncapsulationKey accepted a long encapsulation key")
	}

	dk, err := mlkem1024.NewDecapsulationKey(testSeed())
	if err != nil {
		t.Fatalf("NewDecapsulationKey returned error: %v", err)
	}
	if _, err := dk.Decapsulate(make([]byte, mlkem1024.CiphertextSize-1)); err == nil {
		t.Fatal("Decapsulate accepted a short ciphertext")
	}
	if _, err := dk.Decapsulate(make([]byte, mlkem1024.CiphertextSize+1)); err == nil {
		t.Fatal("Decapsulate accepted a long ciphertext")
	}
}

func TestEncapsulateDecapsulateAgreement(t *testing.T) {
	dk, err := mlkem1024.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}

	sharedKey, ciphertext, err := dk.EncapsulationKey().Encapsulate()
	if err != nil {
		t.Fatalf("Encapsulate returned error: %v", err)
	}
	if len(sharedKey) != mlkem1024.SharedKeySize {
		t.Fatalf("shared key length = %d, want %d", len(sharedKey), mlkem1024.SharedKeySize)
	}
	if len(ciphertext) != mlkem1024.CiphertextSize {
		t.Fatalf("ciphertext length = %d, want %d", len(ciphertext), mlkem1024.CiphertextSize)
	}

	decapsulated, err := dk.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate returned error: %v", err)
	}
	if !bytes.Equal(decapsulated, sharedKey) {
		t.Fatalf("decapsulated shared key = %x, want %x", decapsulated, sharedKey)
	}
}

func testSeed() []byte {
	seed := make([]byte, mlkem1024.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

func BenchmarkGenerateKey(b *testing.B) {
	// TOOD
}

func BenchmarkEncapsulate(b *testing.B) {
	// TODO
}

func BenchmarkDecapsulate(b *testing.B) {
	// TODO
}

func BenchmarkRoundTrip(b *testing.B) {
	// TODO
}

func TestConstantSizes(t *testing.T) {}
