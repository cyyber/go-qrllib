package mldsa87_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/mldsa87"
)

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	clear(buf)
	return len(buf), nil
}

type errReader struct {
	err error
}

func (r errReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestRoundTrip(t *testing.T) {
	public, private, err := mldsa87.GenerateKey(zeroReader{})
	if err != nil {
		t.Fatal(err)
	}
	if len(public.Bytes()) != mldsa87.PublicKeySize {
		t.Fatalf("public key length = %d, want %d", len(public.Bytes()), mldsa87.PublicKeySize)
	}
	if len(private.Bytes()) != mldsa87.PrivateKeySize {
		t.Fatalf("private key length = %d, want %d", len(private.Bytes()), mldsa87.PrivateKeySize)
	}
	if len(private.SecretKeyBytes()) != 4896 {
		t.Fatalf("secret key length = %d, want %d", len(private.SecretKeyBytes()), 4896)
	}

	derivedPublic := private.PublicKey()
	if !bytes.Equal(derivedPublic.Bytes(), public.Bytes()) {
		t.Fatal("private key returned unexpected public key")
	}
	if !public.Equal(derivedPublic) {
		t.Fatal("derived public key is not equal to public key")
	}
	if !private.Equal(private) {
		t.Fatal("private key is not equal to itself")
	}

	publicBytes := public.Bytes()
	publicBytes[0] ^= 1
	if bytes.Equal(public.Bytes(), publicBytes) {
		t.Fatal("PublicKey.Bytes returned internal buffer")
	}
	privateBytes := private.Bytes()
	privateBytes[0] ^= 1
	if bytes.Equal(private.Bytes(), privateBytes) {
		t.Fatal("PrivateKey.Bytes returned internal buffer")
	}

	privateFromSeed, err := mldsa87.NewPrivateKey(private.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(privateFromSeed.PublicKey().Bytes(), public.Bytes()) {
		t.Fatal("NewPrivateKey returned different public key")
	}
	if !bytes.Equal(privateFromSeed.Bytes(), private.Bytes()) {
		t.Fatal("private key seed did not round-trip")
	}

	publicFromBytes, err := mldsa87.NewPublicKey(public.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publicFromBytes.Bytes(), public.Bytes()) {
		t.Fatal("public key encoding did not round-trip")
	}

	message := []byte("test message")
	opts := &mldsa87.Options{Context: []byte("context")}
	signature, err := mldsa87.Sign(zeroReader{}, private, message, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != mldsa87.SignatureSize {
		t.Fatalf("signature length = %d, want %d", len(signature), mldsa87.SignatureSize)
	}
	if !mldsa87.Verify(publicFromBytes, message, signature, opts) {
		t.Fatal("valid signature rejected")
	}
	if mldsa87.Verify(publicFromBytes, []byte("wrong message"), signature, opts) {
		t.Fatal("signature of different message accepted")
	}
	if mldsa87.Verify(publicFromBytes, message, signature, &mldsa87.Options{Context: []byte("other")}) {
		t.Fatal("signature with different context accepted")
	}

	signature1, err := private.Sign(zeroReader{}, message, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !mldsa87.Verify(publicFromBytes, message, signature1, opts) {
		t.Fatal("PrivateKey.Sign signature rejected")
	}

	deterministic, err := mldsa87.SignDeterministic(private, message, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signature, deterministic) {
		t.Fatal("zeroReader signature did not match SignDeterministic")
	}
}

func TestInvalidInputs(t *testing.T) {
	if _, err := mldsa87.NewPrivateKey(nil); err == nil {
		t.Fatal("NewPrivateKey accepted nil seed")
	}
	if _, err := mldsa87.NewPrivateKey(make([]byte, mldsa87.SeedSize+1)); err == nil {
		t.Fatal("NewPrivateKey accepted oversized seed")
	}
	if _, err := mldsa87.NewPublicKey(nil); err == nil {
		t.Fatal("NewPublicKey accepted nil public key")
	}
	if _, err := mldsa87.NewPublicKey(make([]byte, mldsa87.PublicKeySize+1)); err == nil {
		t.Fatal("NewPublicKey accepted oversized public key")
	}

	wantErr := errors.New("random failed")
	if _, _, err := mldsa87.GenerateKey(errReader{err: wantErr}); !errors.Is(err, wantErr) {
		t.Fatalf("GenerateKey returned %v, want %v", err, wantErr)
	}
}
