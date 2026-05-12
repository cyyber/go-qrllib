package falcon1024

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"testing"
)

func Example_falcon1024() {
	pub, priv, err := GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("hello, world")

	sig, err := priv.Sign(nil, msg)
	if err != nil {
		log.Fatal(err)
	}

	if ok := Verify(pub, msg, sig); !ok {
		log.Fatal("invalid signature")
	}
}

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	clear(buf)
	return len(buf), nil
}

func TestGenerateKey(t *testing.T) {
	var zero zeroReader
	public, private, err := GenerateKey(zero)
	if err != nil {
		t.Fatal(err)
	}

	if len(public) != PublicKeySize {
		t.Fatalf("public key has wrong size: got %d, want %d", len(public), PublicKeySize)
	}
	if len(private) != PrivateKeySize {
		t.Fatalf("private key has wrong size: got %d, want %d", len(private), PrivateKeySize)
	}
	cpublic, err := private.Public()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cpublic.(PublicKey), public) {
		t.Fatal("private key returned unexpected public key")
	}

	seed := make([]byte, SeedSize)
	_, _ = zero.Read(seed)
	publicFromSeed, privateFromSeed, err := NewKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publicFromSeed, public) {
		t.Fatal("GenerateKey and NewKeyFromSeed returned different public keys")
	}
	if !bytes.Equal(privateFromSeed, private) {
		t.Fatal("GenerateKey and NewKeyFromSeed returned different private keys")
	}

	_, k2, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(private, k2) {
		t.Errorf("GenerateKey returned the same private key twice")
	}

	_, k3, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(private, k3) {
		t.Errorf("GenerateKey returned the same private key twice")
	}

	// GenerateKey is documented to be the same as NewKeyFromSeed.
	seed = make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	_, k4, err := GenerateKey(bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	_, k4n, err := NewKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k4, k4n) {
		t.Errorf("GenerateKey with seed gave different private key")
	}
}

func TestSignVerify(t *testing.T) {
	var zero zeroReader
	public, private, err := GenerateKey(zero)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("test message")
	sig, err := Sign(zero, private, message)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("signature has wrong size: got %d, want %d", len(sig), SignatureSize)
	}
	if !Verify(public, message, sig) {
		t.Fatal("valid signature rejected")
	}
	if Verify(public, []byte("wrong message"), sig) {
		t.Fatal("signature of different message accepted")
	}

	sig[SignatureSize-1] ^= 1
	if Verify(public, message, sig) {
		t.Fatal("modified signature accepted")
	}
}

func TestPrivateKeySign(t *testing.T) {
	var zero zeroReader
	public, private, err := GenerateKey(zero)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("PrivateKey.Sign message")

	sig, err := private.Sign(zero, message)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(public, message, sig) {
		t.Fatal("PrivateKey.Sign signature rejected")
	}
}

func TestNewKeyFromSeedInvalidSeed(t *testing.T) {
	for _, seed := range [][]byte{
		nil,
		make([]byte, SeedSize-1),
		make([]byte, SeedSize+1),
	} {
		if _, _, err := NewKeyFromSeed(seed); err == nil {
			t.Fatalf("NewKeyFromSeed accepted seed with length %d", len(seed))
		}
	}
}

func TestInvalidPrivateKeyReturnsErrors(t *testing.T) {
	var private PrivateKey
	message := []byte("test message")

	if _, err := private.Public(); err == nil {
		t.Fatal("PrivateKey.Public accepted invalid private key")
	}
	if _, err := private.Sign(nil, message); err == nil {
		t.Fatal("PrivateKey.Sign accepted invalid private key")
	}
	if _, err := Sign(nil, private, message); err == nil {
		t.Fatal("Sign accepted invalid private key")
	}
}

func TestVerifyInvalidInputs(t *testing.T) {
	if Verify(PublicKey{}, nil, nil) {
		t.Fatal("Verify accepted invalid public key")
	}
}

func TestEqual(t *testing.T) {
	public, private, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if !public.Equal(public) {
		t.Errorf("public key is not equal to itself: %q", public)
	}
	derivedPublic, err := private.Public()
	if err != nil {
		t.Fatal(err)
	}
	if !public.Equal(derivedPublic) {
		t.Errorf("private.Public() is not Equal to public: %q", public)
	}
	if !private.Equal(private) {
		t.Errorf("private key is not equal to itself: %q", private)
	}

	otherPub, otherPriv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if public.Equal(otherPub) {
		t.Errorf("different public keys are Equal")
	}
	if private.Equal(otherPriv) {
		t.Errorf("different private keys are Equal")
	}
}

func TestPublicAPIRegression(t *testing.T) {
	// These package-local golden digests are derived from GenerateKey(zeroReader{})
	// and Sign(zeroReader{}, ...).
	// Reference Falcon KATs are covered in crypto/internal/falcon1024.
	var zero zeroReader
	public, private, err := GenerateKey(zero)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("Falcon-1024 public API golden test")
	signature, err := Sign(zero, private, message)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(public, message, signature) {
		t.Fatal("golden signature failed verification")
	}

	checkSHA256(t, "public key", public, "e6002a1133c82aa79254740e864960db9724b3f042ea8798d14cabddb8ef56be")
	checkSHA256(t, "private key", private, "8692afea3c1d5cfcbb76f9867b30cc11bc6eca980a1f21abd7f2935a607d986b")
	checkSHA256(t, "signature", signature, "31112e24ca1ed78a60fb2812591ce471dab85a77bda9d1b1af0fe7d52e92e35f")
}

func checkSHA256(t *testing.T, name string, got []byte, want string) {
	t.Helper()

	sum := sha256.Sum256(got)
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("%s digest mismatch: got %s, want %s", name, got, want)
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	var zero zeroReader
	for b.Loop() {
		if _, _, err := GenerateKey(zero); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewKeyFromSeed(b *testing.B) {
	seed := make([]byte, SeedSize)
	for b.Loop() {
		_, _, err := NewKeyFromSeed(seed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSigning(b *testing.B) {
	var zero zeroReader
	_, priv, err := GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	for b.Loop() {
		_, err := Sign(zero, priv, message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerification(b *testing.B) {
	var zero zeroReader
	pub, priv, err := GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature, err := Sign(zero, priv, message)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		Verify(pub, message, signature)
	}
}
