package mldsa87_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/mldsa87"
)

// Thread safety tests for the public ML-DSA-87 API.
//
// Run with:
//
//	go test -race ./crypto/mldsa87

func TestThreadSafetyConcurrentVerify(t *testing.T) {
	publicKey, privateKey, err := mldsa87.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	msg := []byte("test message for concurrent verification")
	opts := &mldsa87.Options{Context: []byte("context")}

	sig, err := privateKey.Sign(nil, msg, opts)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errs := make(chan string, numGoroutines)
	for range numGoroutines {
		go func() {
			defer wg.Done()
			if !mldsa87.Verify(publicKey, msg, sig, opts) {
				errs <- "concurrent verification failed"
			}
		}()
	}

	wg.Wait()
	close(errs)
	for errMsg := range errs {
		t.Error(errMsg)
	}
}

func TestThreadSafetyConcurrentSign(t *testing.T) {
	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errs := make(chan string, numGoroutines)
	for i := range numGoroutines {
		go func(idx int) {
			defer wg.Done()

			publicKey, privateKey, err := mldsa87.GenerateKey(nil)
			if err != nil {
				errs <- fmt.Sprintf("GenerateKey(%d) failed: %v", idx, err)
				return
			}

			msg := []byte("test message")
			sig, err := privateKey.Sign(nil, msg, nil)
			if err != nil {
				errs <- fmt.Sprintf("Sign(%d) failed: %v", idx, err)
				return
			}
			if !mldsa87.Verify(publicKey, msg, sig, nil) {
				errs <- fmt.Sprintf("Verify(%d) failed", idx)
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for errMsg := range errs {
		t.Error(errMsg)
	}
}

func TestThreadSafetyConcurrentKeyGeneration(t *testing.T) {
	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	publicKeys := make(chan *mldsa87.PublicKey, numGoroutines)
	errs := make(chan string, numGoroutines)
	for i := range numGoroutines {
		go func(idx int) {
			defer wg.Done()
			publicKey, _, err := mldsa87.GenerateKey(nil)
			if err != nil {
				errs <- fmt.Sprintf("GenerateKey(%d) failed: %v", idx, err)
				return
			}
			publicKeys <- publicKey
		}(i)
	}

	wg.Wait()
	close(publicKeys)
	close(errs)

	for errMsg := range errs {
		t.Error(errMsg)
	}

	seen := make(map[string]bool)
	for publicKey := range publicKeys {
		publicKeyBytes := publicKey.Bytes()
		key := string(publicKeyBytes)
		if seen[key] {
			t.Error("duplicate public key generated")
		}
		seen[key] = true
	}
}

func TestThreadSafetySamePrivateKeySign(t *testing.T) {
	publicKey, privateKey, err := mldsa87.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	opts := &mldsa87.Options{Context: []byte("context")}

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errs := make(chan string, numGoroutines)
	for i := range numGoroutines {
		go func(idx int) {
			defer wg.Done()
			msg := []byte("message")

			sig, err := privateKey.Sign(nil, msg, opts)
			if err != nil {
				errs <- fmt.Sprintf("Sign(%d) failed: %v", idx, err)
				return
			}
			if !mldsa87.Verify(publicKey, msg, sig, opts) {
				errs <- fmt.Sprintf("Verify(%d) failed", idx)
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for errMsg := range errs {
		t.Error(errMsg)
	}
}
