package mldsa87_test

import (
	"sync"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/mldsa87"
)

type MLDSA87 struct {
	publicKey  *mldsa87.PublicKey
	privateKey *mldsa87.PrivateKey
}

func New() (*MLDSA87, error) {
	publicKey, privateKey, err := mldsa87.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return &MLDSA87{publicKey: publicKey, privateKey: privateKey}, nil
}

func (mldsa *MLDSA87) Sign(ctx, msg []byte) ([]byte, error) {
	return mldsa.privateKey.Sign(nil, msg, &mldsa87.Options{Context: ctx})
}

func (mldsa *MLDSA87) GetPK() mldsa87.PublicKey {
	return *mldsa.publicKey
}

func Verify(ctx, msg, sig []byte, pk *mldsa87.PublicKey) bool {
	return mldsa87.Verify(pk, msg, sig, &mldsa87.Options{Context: ctx})
}

// Thread safety tests for ML-DSA-87 (TST-006)
// Run with: go test -race ./crypto/mldsa87/...
//
// These tests verify that concurrent operations don't cause data races.

// TestThreadSafetyConcurrentVerify tests parallel verification with shared public key
func TestThreadSafetyConcurrentVerify(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message for concurrent verification")
	ctx := []byte("context")

	sig, err := mldsa.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	pk := mldsa.GetPK()

	// Run many concurrent verifications
	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			if !Verify(ctx, msg, sig, &pk) {
				errors <- nil // Use nil to indicate verification failure
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		if err == nil {
			t.Error("Concurrent verification failed")
		}
	}
}

// TestThreadSafetyConcurrentSign tests parallel signing with different instances
func TestThreadSafetyConcurrentSign(t *testing.T) {
	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errors := make(chan string, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			// Each goroutine creates its own instance
			mldsa, err := New()
			if err != nil {
				errors <- "Failed to create instance"
				return
			}

			msg := []byte("test message")
			ctx := []byte{}

			sig, err := mldsa.Sign(ctx, msg)
			if err != nil {
				errors <- "Failed to sign"
				return
			}

			pk := mldsa.GetPK()
			if !Verify(ctx, msg, sig, &pk) {
				errors <- "Verification failed"
				return
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for errMsg := range errors {
		t.Error(errMsg)
	}
}

// TestThreadSafetyConcurrentKeyGeneration tests parallel key generation
func TestThreadSafetyConcurrentKeyGeneration(t *testing.T) {
	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	results := make(chan *MLDSA87, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			mldsa, err := New()
			if err != nil {
				t.Errorf("Failed to create MLDSA87: %v", err)
				return
			}
			results <- mldsa
		}()
	}

	wg.Wait()
	close(results)

	// Verify all instances are unique
	pks := make(map[string]bool)
	for mldsa := range results {
		if mldsa == nil {
			continue
		}
		pk := mldsa.GetPK()
		pkBytes := pk.Bytes()
		pkStr := string(pkBytes)
		if pks[pkStr] {
			t.Error("Duplicate public key generated")
		}
		pks[pkStr] = true
	}
}

// TestThreadSafetySameInstanceSign tests signing from same instance (should be safe for ML-DSA)
func TestThreadSafetySameInstanceSign(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	pk := mldsa.GetPK()
	ctx := []byte{}

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			msg := []byte("message")

			sig, err := mldsa.Sign(ctx, msg)
			if err != nil {
				t.Errorf("Sign failed: %v", err)
				return
			}

			if !Verify(ctx, msg, sig, &pk) {
				t.Error("Verification failed")
			}
		}(i)
	}

	wg.Wait()
}
