package mlkem1024_test

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/internal/mlkem1024"
	. "github.com/theQRL/go-qrllib/crypto/mlkem1024"
)

func TestRoundTrip(t *testing.T) {
	dk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	Ke, c, err := ek.Encapsulate()
	if err != nil {
		t.Fatal(err)
	}
	Kd, err := dk.Decapsulate(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Ke, Kd) {
		t.Fail()
	}

	ek1, err := NewEncapsulationKey(ek.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ek.Bytes(), ek1.Bytes()) {
		t.Fail()
	}

	dk1, err := NewDecapsulationKey(dk.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dk.Bytes(), dk1.Bytes()) {
		t.Fail()
	}

	Ke1, c1, err := ek1.Encapsulate()
	if err != nil {
		t.Fatal(err)
	}
	Kd1, err := dk1.Decapsulate(c1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Ke1, Kd1) {
		t.Fail()
	}

	dk2, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dk.EncapsulationKey().Bytes(), dk2.EncapsulationKey().Bytes()) {
		t.Fail()
	}
	if bytes.Equal(dk.Bytes(), dk2.Bytes()) {
		t.Fail()
	}

	Ke2, c2, err := dk.EncapsulationKey().Encapsulate()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c, c2) {
		t.Fail()
	}
	if bytes.Equal(Ke, Ke2) {
		t.Fail()
	}
}

func TestInvalidInputLengths(t *testing.T) {
	if _, err := NewDecapsulationKey(make([]byte, SeedSize-1)); err == nil {
		t.Fatal("NewDecapsulationKey accepted a short seed")
	}
	if _, err := NewDecapsulationKey(make([]byte, SeedSize+1)); err == nil {
		t.Fatal("NewDecapsulationKey accepted a long seed")
	}
	if _, err := NewEncapsulationKey(make([]byte, EncapsulationKeySize-1)); err == nil {
		t.Fatal("NewEncapsulationKey accepted a short encapsulation key")
	}
	if _, err := NewEncapsulationKey(make([]byte, EncapsulationKeySize+1)); err == nil {
		t.Fatal("NewEncapsulationKey accepted a long encapsulation key")
	}

	dk, err := NewDecapsulationKey(testSeed())
	if err != nil {
		t.Fatalf("NewDecapsulationKey returned error: %v", err)
	}
	if _, err := dk.Decapsulate(make([]byte, CiphertextSize-1)); err == nil {
		t.Fatal("Decapsulate accepted a short ciphertext")
	}
	if _, err := dk.Decapsulate(make([]byte, CiphertextSize+1)); err == nil {
		t.Fatal("Decapsulate accepted a long ciphertext")
	}
}

func TestEncapsulateDecapsulateAgreement(t *testing.T) {
	dk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}

	sharedKey, ciphertext, err := dk.EncapsulationKey().Encapsulate()
	if err != nil {
		t.Fatalf("Encapsulate returned error: %v", err)
	}
	if len(sharedKey) != SharedKeySize {
		t.Fatalf("shared key length = %d, want %d", len(sharedKey), SharedKeySize)
	}
	if len(ciphertext) != CiphertextSize {
		t.Fatalf("ciphertext length = %d, want %d", len(ciphertext), CiphertextSize)
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
	seed := make([]byte, SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

// TODO
var sink byte

func BenchmarkGenerateKey(b *testing.B) {
	var d, z [32]byte
	_, _ = rand.Read(d[:])
	_, _ = rand.Read(z[:])
	for b.Loop() {
		dk := mlkem1024.GenerateKeyInternal(&d, &z)
		sink ^= dk.EncapsulationKey().Bytes()[0]
	}
}

func BenchmarkEncapsulate(b *testing.B) {
	seed := make([]byte, SeedSize)
	_, _ = rand.Read(seed[:])

	dk, err := NewDecapsulationKey(seed)
	if err != nil {
		b.Fatal(err)
	}
	ekBytes := dk.EncapsulationKey().Bytes()

	for b.Loop() {
		ek, err := NewEncapsulationKey(ekBytes)
		if err != nil {
			b.Fatal(err)
		}

		sharedKey, ciphertext, err := ek.Encapsulate()
		if err != nil {
			b.Fatal(err)
		}

		sink ^= ciphertext[0] ^ sharedKey[0]
	}

}

func BenchmarkDecapsulate(b *testing.B) {
	dk, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	_, ciphertext, err := ek.Encapsulate()
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		sharedKey, _ := dk.Decapsulate(ciphertext)
		sink ^= sharedKey[0]
	}
}

func BenchmarkCompareGenerateKey1024(b *testing.B) {
	b.Run("ours", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			dk, err := GenerateKey()
			if err != nil {
				b.Fatal(err)
			}
			sink ^= dk.EncapsulationKey().Bytes()[0]
		}
	})
	b.Run("stdlib", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			dk, err := mlkem.GenerateKey1024()
			if err != nil {
				b.Fatal(err)
			}
			sink ^= dk.EncapsulationKey().Bytes()[0]
		}
	})
}

func BenchmarkCompareEncapsulate1024(b *testing.B) {
	seed := make([]byte, SeedSize)
	_, _ = rand.Read(seed)

	oursDK, err := NewDecapsulationKey(seed)
	if err != nil {
		b.Fatal(err)
	}
	oursEKBytes := oursDK.EncapsulationKey().Bytes()

	stdlibDK, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		b.Fatal(err)
	}
	stdlibEKBytes := stdlibDK.EncapsulationKey().Bytes()

	b.Run("ours", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			ek, err := NewEncapsulationKey(oursEKBytes)
			if err != nil {
				b.Fatal(err)
			}
			sharedKey, ciphertext, err := ek.Encapsulate()
			if err != nil {
				b.Fatal(err)
			}
			sink ^= ciphertext[0] ^ sharedKey[0]
		}
	})
	b.Run("stdlib", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			ek, err := mlkem.NewEncapsulationKey1024(stdlibEKBytes)
			if err != nil {
				b.Fatal(err)
			}
			sharedKey, ciphertext := ek.Encapsulate()
			sink ^= ciphertext[0] ^ sharedKey[0]
		}
	})
}

func BenchmarkCompareDecapsulate1024(b *testing.B) {
	oursDK, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	_, oursCiphertext, err := oursDK.EncapsulationKey().Encapsulate()
	if err != nil {
		b.Fatal(err)
	}

	stdlibDK, err := mlkem.GenerateKey1024()
	if err != nil {
		b.Fatal(err)
	}
	_, stdlibCiphertext := stdlibDK.EncapsulationKey().Encapsulate()

	b.Run("ours", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sharedKey, err := oursDK.Decapsulate(oursCiphertext)
			if err != nil {
				b.Fatal(err)
			}
			sink ^= sharedKey[0]
		}
	})
	b.Run("stdlib", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sharedKey, err := stdlibDK.Decapsulate(stdlibCiphertext)
			if err != nil {
				b.Fatal(err)
			}
			sink ^= sharedKey[0]
		}
	})
}

func TestConstantSizes(t *testing.T) {
	if SharedKeySize != mlkem1024.SharedKeySize {
		t.Errorf("SharedKeySize mismatch: got %d, want %d", SharedKeySize, mlkem.SharedKeySize)
	}

	if SeedSize != mlkem1024.SeedSize {
		t.Errorf("SeedSize mismatch: got %d, want %d", SeedSize, mlkem.SeedSize)
	}

	if CiphertextSize != mlkem1024.CiphertextSize {
		t.Errorf("CiphertextSize mismatch: got %d, want %d", CiphertextSize, mlkem1024.CiphertextSize)
	}

	if EncapsulationKeySize != mlkem1024.EncapsulationKeySize {
		t.Errorf("EncapsulationKeySize mismatch: got %d, want %d", EncapsulationKeySize, mlkem1024.EncapsulationKeySize)
	}
}
