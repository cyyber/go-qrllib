// mldsa87_verify.go - Verify pq-crystals ML-DSA-87 signature with go-qrllib
package main

import (
	"fmt"
	"os"

	"github.com/theQRL/go-qrllib/crypto/mldsa87"
)

func main() {
	pkBytes, _ := os.ReadFile("/tmp/ref_mldsa_pk.bin")
	sigBytes, _ := os.ReadFile("/tmp/ref_mldsa_sig.bin")
	msgBytes, _ := os.ReadFile("/tmp/ref_mldsa_msg.bin")
	ctxBytes, _ := os.ReadFile("/tmp/ref_mldsa_ctx.bin")

	if len(pkBytes) != mldsa87.PublicKeySize {
		fmt.Fprintf(os.Stderr, "PK size mismatch: got %d, expected %d\n",
			len(pkBytes), mldsa87.PublicKeySize)
		os.Exit(1)
	}
	if len(sigBytes) != mldsa87.SignatureSize {
		fmt.Fprintf(os.Stderr, "Sig size mismatch: got %d, expected %d\n",
			len(sigBytes), mldsa87.SignatureSize)
		os.Exit(1)
	}

	publicKey, err := mldsa87.NewPublicKey(pkBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Public key error: %v\n", err)
		os.Exit(1)
	}

	valid := mldsa87.Verify(publicKey, msgBytes, sigBytes, &mldsa87.Options{Context: ctxBytes})

	fmt.Printf("go-qrllib ML-DSA-87 verifier:\n")
	fmt.Printf("  PK size:  %d bytes\n", len(pkBytes))
	fmt.Printf("  Sig size: %d bytes\n", len(sigBytes))
	fmt.Printf("  Context:  %s\n", string(ctxBytes))
	fmt.Printf("  Verification: %s\n", map[bool]string{true: "PASSED", false: "FAILED"}[valid])

	if !valid {
		os.Exit(1)
	}
}
