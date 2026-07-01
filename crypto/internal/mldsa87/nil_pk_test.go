// Regression tests for TOB-QRLLIB-11: ML-DSA Verify panics on a
// nil public key.
//
// The audit's proof-of-concept (figure 11.4) deferred a recover() and
// asserted that recover() != nil — i.e. a panic occurred. These tests
// invert that assertion: with the nil-check guards now in place, the
// public surface MUST return a clean refusal (false from Verify) and MUST NOT
// panic. A regression that removes the guard would re-introduce the panic,
// which these tests would catch.

package mldsa87

import (
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// fixtureSign produces a real signature so tests have well-formed material to
// feed into Verify. Using real material rules out "Verify returned false
// because the signature was malformed" as an alternative explanation when
// asserting the nil-pk refusal path.
func fixtureSign(t *testing.T) (msg []byte, ctx []byte, sig [CRYPTO_BYTES]uint8) {
	t.Helper()
	mldsa, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("setup: New failed: %v", err)
	}
	msg = []byte("nil-pk regression test message")
	ctx = []byte("test-ctx")
	sig, err = mldsa.Sign(nil, ctx, msg)
	if err != nil {
		t.Fatalf("setup: Sign failed: %v", err)
	}
	return msg, ctx, sig
}

func TestVerify_NilPublicKey_ReturnsFalseNoPanic(t *testing.T) {
	msg, ctx, sig := fixtureSign(t)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Verify panicked on nil public key: %v", r)
		}
	}()

	if Verify(ctx, msg, sig, nil) {
		t.Fatal("Verify(nil pk) returned true; want false")
	}
}

func TestCryptoSignVerify_NilPublicKey_ReturnsErrPublicKeyNil(t *testing.T) {
	msg, ctx, sig := fixtureSign(t)

	ok, err := cryptoSignVerify(sig, msg, ctx, nil)
	if ok {
		t.Error("cryptoSignVerify(nil pk) returned ok=true; want false")
	}
	if !errors.Is(err, cryptoerrors.ErrPublicKeyNil) {
		t.Errorf("cryptoSignVerify(nil pk) err = %v; want ErrPublicKeyNil", err)
	}
}
