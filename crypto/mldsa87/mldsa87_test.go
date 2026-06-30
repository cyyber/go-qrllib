package mldsa87_test

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"testing"

	internal "github.com/theQRL/go-qrllib/crypto/internal/mldsa87"
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

	derivedPublic := private.Public().(*mldsa87.PublicKey)
	if !bytes.Equal(derivedPublic.Bytes(), public.Bytes()) {
		t.Fatal("private key returned unexpected public key")
	}
	if !bytes.Equal(private.PublicKey().Bytes(), public.Bytes()) {
		t.Fatal("PrivateKey.PublicKey returned unexpected public key")
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

	zeroSeed := make([]byte, mldsa87.SeedSize)
	_, _ = zeroReader{}.Read(zeroSeed)
	privateFromZeroSeed, err := mldsa87.NewPrivateKey(zeroSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(privateFromZeroSeed.PublicKey().Bytes(), public.Bytes()) {
		t.Fatal("GenerateKey and NewPrivateKey returned different public keys")
	}
	if !bytes.Equal(privateFromZeroSeed.Bytes(), private.Bytes()) {
		t.Fatal("GenerateKey and NewPrivateKey returned different private keys")
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

	modifiedSignature := bytes.Clone(signature)
	modifiedSignature[mldsa87.SignatureSize-1] ^= 1
	if mldsa87.Verify(publicFromBytes, message, modifiedSignature, opts) {
		t.Fatal("modified signature accepted")
	}

	otherSeed := bytes.Repeat([]byte{1}, mldsa87.SeedSize)
	otherPublic, otherPrivate, err := mldsa87.GenerateKey(bytes.NewReader(otherSeed))
	if err != nil {
		t.Fatal(err)
	}
	if public.Equal(otherPublic) {
		t.Fatal("different public keys are Equal")
	}
	if mldsa87.Verify(otherPublic, message, signature, opts) {
		t.Fatal("signature accepted with a different public key")
	}
	if private.Equal(otherPrivate) {
		t.Fatal("different private keys are Equal")
	}
	if bytes.Equal(private.Bytes(), otherPrivate.Bytes()) {
		t.Fatal("GenerateKey returned the same private key twice")
	}

	_, randomPrivate, err := mldsa87.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(randomPrivate.Bytes()) != mldsa87.PrivateKeySize {
		t.Fatalf("random private key length = %d, want %d", len(randomPrivate.Bytes()), mldsa87.PrivateKeySize)
	}

	seed := testSeed()
	_, generatedFromSeed, err := mldsa87.GenerateKey(bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	privateFromTestSeed, err := mldsa87.NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generatedFromSeed.Bytes(), privateFromTestSeed.Bytes()) {
		t.Fatal("GenerateKey with seed gave different private key")
	}

	deterministic, err := mldsa87.SignDeterministic(private, message, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signature, deterministic) {
		t.Fatal("zeroReader signature did not match SignDeterministic")
	}
}

func testSeed() []byte {
	seed := make([]byte, mldsa87.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

func TestInvalidInputs(t *testing.T) {
	for _, seed := range [][]byte{
		nil,
		make([]byte, mldsa87.SeedSize-1),
		make([]byte, mldsa87.SeedSize+1),
	} {
		if _, err := mldsa87.NewPrivateKey(seed); err == nil {
			t.Fatalf("NewPrivateKey accepted seed with length %d", len(seed))
		}
	}

	public, private, err := mldsa87.GenerateKey(zeroReader{})
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("test message")
	signature, err := mldsa87.Sign(zeroReader{}, private, message, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, publicKey := range [][]byte{
		nil,
		make([]byte, mldsa87.PublicKeySize-1),
		make([]byte, mldsa87.PublicKeySize+1),
	} {
		if _, err := mldsa87.NewPublicKey(publicKey); err == nil {
			t.Fatalf("NewPublicKey accepted invalid public key with length %d", len(publicKey))
		}
	}

	for _, sig := range [][]byte{
		nil,
		make([]byte, mldsa87.SignatureSize-1),
		make([]byte, mldsa87.SignatureSize+1),
		append([]byte{signature[0] ^ 0xFF}, signature[1:]...),
	} {
		if mldsa87.Verify(public, message, sig, nil) {
			t.Fatalf("Verify accepted invalid signature with length %d", len(sig))
		}
	}

	wantErr := errors.New("random failed")
	if _, _, err := mldsa87.GenerateKey(errReader{err: wantErr}); !errors.Is(err, wantErr) {
		t.Fatalf("GenerateKey returned %v, want %v", err, wantErr)
	}
}

func TestAccumulated(t *testing.T) {
	const expected = "5d76cd68e6caf971cf25b6f39b5eb9b9ba626dabb3c58231a8607e8efbc1950b"

	s := sha3.NewSHAKE128()
	o := sha3.NewSHAKE128()
	seed := make([]byte, mldsa87.SeedSize)
	signSeed := make([]byte, mldsa87.SeedSize)
	var message [32]byte

	for range 16 {
		_, _ = s.Read(seed)
		private, err := mldsa87.NewPrivateKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		public := private.Public().(*mldsa87.PublicKey)
		_, _ = o.Write(public.Bytes())
		_, _ = o.Write(private.Bytes())

		_, _ = s.Read(message[:])
		_, _ = s.Read(signSeed)
		signature, err := mldsa87.Sign(bytes.NewReader(signSeed), private, message[:], nil)
		if err != nil {
			t.Fatal(err)
		}
		if !mldsa87.Verify(public, message[:], signature, nil) {
			t.Fatal("valid signature rejected")
		}
		_, _ = o.Write(signature)
	}

	var digest [32]byte
	_, _ = o.Read(digest[:])
	got := hex.EncodeToString(digest[:])
	if got != expected {
		t.Errorf("got %s, expected %s", got, expected)
	}
}

func TestConstantSizes(t *testing.T) {
	if mldsa87.SeedSize != internal.SEED_BYTES {
		t.Errorf("SeedSize mismatch: got %d, want %d", mldsa87.SeedSize, internal.SEED_BYTES)
	}

	if mldsa87.PrivateKeySize != internal.SEED_BYTES {
		t.Errorf("PrivateKeySize mismatch: got %d, want %d", mldsa87.PrivateKeySize, internal.SEED_BYTES)
	}

	if mldsa87.PublicKeySize != internal.CRYPTO_PUBLIC_KEY_BYTES {
		t.Errorf("PublicKeySize mismatch: got %d, want %d", mldsa87.PublicKeySize, internal.CRYPTO_PUBLIC_KEY_BYTES)
	}

	if mldsa87.SignatureSize != internal.CRYPTO_BYTES {
		t.Errorf("SignatureSize mismatch: got %d, want %d", mldsa87.SignatureSize, internal.CRYPTO_BYTES)
	}
}
