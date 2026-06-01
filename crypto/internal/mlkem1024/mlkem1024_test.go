package mlkem1024

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// These KATs use fixed d || z and encapsulation randomness. Expected values are
// derived from FIPS 203 and cross-checked against Go's crypto/mlkem package.
// Sources: https://doi.org/10.6028/NIST.FIPS.203,
// https://go.dev/src/crypto/mlkem/, and
// https://go.dev/src/crypto/mlkem/mlkemtest/.

func TestNewDecapsulationKeyKAT(t *testing.T) {
	seed := katSeed()
	dk, err := NewDecapsulationKey(seed[:])
	if err != nil {
		t.Fatalf("NewDecapsulationKey returned error: %v", err)
	}

	if got := dk.Bytes(); !bytes.Equal(got, seed[:]) {
		t.Fatalf("decapsulation key bytes = %x, want %x", got, seed)
	}
	if got := hex.EncodeToString(dk.rho[:]); got != "44b6c66984a868aa92fa02227a086950eb0c8701ed58dc628776b983882e1175" {
		t.Fatalf("rho = %s, want %s", got, "44b6c66984a868aa92fa02227a086950eb0c8701ed58dc628776b983882e1175")
	}
	if got := hex.EncodeToString(dk.h[:]); got != "61349e5c131a7e116a0463861d7d18663c5627c38c7147ddaadfd48acd7a4535" {
		t.Fatalf("H(ekPKE) = %s, want %s", got, "61349e5c131a7e116a0463861d7d18663c5627c38c7147ddaadfd48acd7a4535")
	}

	ek := dk.EncapsulationKey().Bytes()
	if len(ek) != EncapsulationKeySize {
		t.Fatalf("encapsulation key length = %d, want %d", len(ek), EncapsulationKeySize)
	}
	checkBytesHash(t, "EncapsulationKey().Bytes", ek, "c7b8fa0aa471d5ae18922d6ccad5b31e1d84f92ae723abfd13747018740a8530")
}

func TestEncapsulateInternalKAT(t *testing.T) {
	seed := katSeed()
	dk, err := NewDecapsulationKey(seed[:])
	if err != nil {
		t.Fatalf("NewDecapsulationKey returned error: %v", err)
	}

	m := katMessage()
	var ct [CiphertextSize]byte
	sharedKey := encapsulateTo(&ct, dk.EncapsulationKey(), &m)
	ciphertext := ct[:]

	if got := hex.EncodeToString(sharedKey); got != "a9f52838faed39482c5769f3b8ea6152a09ca981da3a8816ced34be298e54e95" {
		t.Fatalf("shared key = %s, want %s", got, "a9f52838faed39482c5769f3b8ea6152a09ca981da3a8816ced34be298e54e95")
	}
	if len(ciphertext) != CiphertextSize {
		t.Fatalf("ciphertext length = %d, want %d", len(ciphertext), CiphertextSize)
	}
	checkBytesHash(t, "ciphertext", ciphertext, "80d9a3e8af2343685270dace8098e100c634dab5d503939b3e26053f86ee3202")

	decapsulated, err := dk.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate returned error: %v", err)
	}
	if !bytes.Equal(decapsulated, sharedKey) {
		t.Fatalf("decapsulated shared key = %x, want %x", decapsulated, sharedKey)
	}
}

func TestNewEncapsulationKeyExpandsMatrix(t *testing.T) {
	seed := katSeed()
	dk, err := NewDecapsulationKey(seed[:])
	if err != nil {
		t.Fatalf("NewDecapsulationKey returned error: %v", err)
	}

	ek, err := NewEncapsulationKey(dk.EncapsulationKey().Bytes())
	if err != nil {
		t.Fatalf("NewEncapsulationKey returned error: %v", err)
	}

	var want ringElement
	sampleNTT(&want, &ek.rho, 0, 0)
	if ek.a[0] != want {
		t.Fatal("NewEncapsulationKey did not regenerate A from rho")
	}

	// Check a non-diagonal entry so a row/column index swap is caught.
	sampleNTT(&want, &ek.rho, 2, 1)
	if ek.a[1*k+2] != want {
		t.Fatal("NewEncapsulationKey did not regenerate A from rho")
	}
}

func TestEncapsulationKeyBytesReturnsCopy(t *testing.T) {
	seed := katSeed()
	dk, err := NewDecapsulationKey(seed[:])
	if err != nil {
		t.Fatalf("NewDecapsulationKey returned error: %v", err)
	}

	raw := dk.EncapsulationKey().Bytes()
	ek, err := NewEncapsulationKey(raw)
	if err != nil {
		t.Fatalf("NewEncapsulationKey returned error: %v", err)
	}

	raw[0] ^= 0xff
	if bytes.Equal(ek.Bytes(), raw) {
		t.Fatal("NewEncapsulationKey retained caller-owned encapsulation key bytes")
	}

	encoded := ek.Bytes()
	encoded[0] ^= 0xff
	if bytes.Equal(ek.Bytes(), encoded) {
		t.Fatal("EncapsulationKey.Bytes returned mutable internal storage")
	}
}

func katSeed() [SeedSize]byte {
	var seed [SeedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

func katMessage() [32]byte {
	var m [32]byte
	for i := range m {
		m[i] = byte(255 - 7*i)
	}
	return m
}
