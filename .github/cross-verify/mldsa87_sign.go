// mldsa87_sign.go - Generate ML-DSA-87 signature for cross-verification
package main

import (
	"fmt"
	"os"

	"github.com/theQRL/go-qrllib/crypto/mldsa87"
)

func main() {
	// Deterministic seed for reproducibility
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}

	privateKey, err := mldsa87.NewPrivateKey(seed[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	publicKey := privateKey.PublicKey()
	ctx := []byte("test")
	msg := []byte("ML-DSA-87 cross-implementation verification")
	opts := &mldsa87.Options{Context: ctx}

	sig, err := mldsa87.Sign(zeroReader{}, privateKey, msg, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sign error: %v\n", err)
		os.Exit(1)
	}

	// Self-verify
	if !mldsa87.Verify(publicKey, msg, sig, opts) {
		fmt.Fprintln(os.Stderr, "Self-verification failed!")
		os.Exit(1)
	}

	// Write files
	pk := publicKey.Bytes()
	os.WriteFile("/tmp/mldsa_pk.bin", pk, 0644)
	os.WriteFile("/tmp/mldsa_sig.bin", sig, 0644)
	os.WriteFile("/tmp/mldsa_msg.bin", msg, 0644)
	os.WriteFile("/tmp/mldsa_ctx.bin", ctx, 0644)

	fmt.Printf("go-qrllib ML-DSA-87:\n")
	fmt.Printf("  PK size:  %d bytes\n", len(pk))
	fmt.Printf("  Sig size: %d bytes\n", len(sig))
	fmt.Printf("  Context:  %s\n", string(ctx))
	fmt.Printf("  Self-verify: PASSED\n")
}

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	clear(buf)
	return len(buf), nil
}
