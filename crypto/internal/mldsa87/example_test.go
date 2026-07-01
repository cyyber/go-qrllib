package mldsa87_test

import (
	"fmt"

	"github.com/theQRL/go-qrllib/crypto/internal/mldsa87"
)

// Example demonstrates basic ML-DSA-87 signature operations.
func Example() {
	// Generate a new ML-DSA-87 private key.
	m, err := mldsa87.GenerateKey(nil)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer m.Zeroize() // Clear sensitive key material when done

	// Sign a message with context (FIPS 204 requirement)
	ctx := []byte("my-application")
	message := []byte("Hello, FIPS 204!")
	signature, err := m.Sign(nil, ctx, message)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Verify the signature.
	valid := mldsa87.VerifySignature(m.PublicKey(), message, signature[:], ctx) == nil
	fmt.Println("Signature valid:", valid)
	// Output: Signature valid: true
}

// ExampleGenerateKey demonstrates creating an ML-DSA-87 private key.
func ExampleGenerateKey() {
	// Generate with random seed.
	m, err := mldsa87.GenerateKey(nil)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer m.Zeroize()

	fmt.Println("Public key size:", len(m.PublicKey().Bytes()))
	// Output: Public key size: 2592
}

// ExampleNewPrivateKey demonstrates deterministic key generation.
func ExampleNewPrivateKey() {
	// Create from a specific seed for reproducible keys
	var seed [mldsa87.SEED_BYTES]uint8
	copy(seed[:], []byte("my-32-byte-seed-for-testing!"))

	m, err := mldsa87.NewPrivateKey(seed[:])
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer m.Zeroize()

	// Same seed always produces same keys
	pk := m.PublicKey().Bytes()
	fmt.Println("Public key generated:", len(pk) == mldsa87.CRYPTO_PUBLIC_KEY_BYTES)
	// Output: Public key generated: true
}

// ExamplePrivateKey_Sign demonstrates signing with context.
func ExamplePrivateKey_Sign() {
	m, _ := mldsa87.GenerateKey(nil)
	defer m.Zeroize()

	// FIPS 204 requires a context parameter for domain separation
	// Use empty context if not needed, but consider using application-specific context
	ctx := []byte("my-application") // application-specific context for domain separation
	message := []byte("transaction data")

	signature, err := m.Sign(nil, ctx, message)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Signature size:", len(signature))
	// Output: Signature size: 4627
}

// ExampleVerify demonstrates signature verification with context.
func ExampleVerify() {
	m, _ := mldsa87.GenerateKey(nil)
	defer m.Zeroize()

	ctx := []byte("test-context")
	message := []byte("verify me")
	signature, _ := m.Sign(nil, ctx, message)

	// Verify requires the same context used during signing
	valid := mldsa87.VerifySignature(m.PublicKey(), message, signature[:], ctx) == nil
	fmt.Println("Valid signature:", valid)

	// Wrong context fails verification
	wrongCtx := []byte("wrong-context")
	valid = mldsa87.VerifySignature(m.PublicKey(), message, signature[:], wrongCtx) == nil
	fmt.Println("Wrong context:", valid)
	// Output:
	// Valid signature: true
	// Wrong context: false
}
