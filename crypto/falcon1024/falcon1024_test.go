package falcon1024

import (
	"bytes"
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

type countingReader byte

func (r countingReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = byte(r) + byte(i)
	}
	return len(buf), nil
}

func TestGenerateKey(t *testing.T) {
	public, private, err := GenerateKey(countingReader(0))
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
	countingReader(0).Read(seed)
	publicFromSeed, privateFromSeed := mustNewKeyFromSeed(t, seed)
	if !bytes.Equal(publicFromSeed, public) {
		t.Fatal("GenerateKey and NewKeyFromSeed returned different public keys")
	}
	if !bytes.Equal(privateFromSeed, private) {
		t.Fatal("GenerateKey and NewKeyFromSeed returned different private keys")
	}
}

func TestSignVerify(t *testing.T) {
	public, private := mustNewKeyFromSeed(t, testSeed())

	message := []byte("test message")
	sig, err := Sign(countingReader(0xa5), private, message)
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
	public, private := mustNewKeyFromSeed(t, testSeed())
	message := []byte("PrivateKey.Sign message")

	sig, err := private.Sign(countingReader(0x5a), message)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(public, message, sig) {
		t.Fatal("PrivateKey.Sign signature rejected")
	}
}

func TestNewKeyFromSeedInvalidSeed(t *testing.T) {
	if _, _, err := NewKeyFromSeed(nil); err == nil {
		t.Fatal("NewKeyFromSeed accepted invalid seed")
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

func TestGolden(t *testing.T) {
	public, private := mustNewKeyFromSeed(t, testSeed())

	message := []byte("Falcon-1024 public API golden test")
	signature, err := Sign(countingReader(0xa5), private, message)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(public, message, signature) {
		t.Fatal("golden signature failed verification")
	}

	checkSHA256(t, "public key", public, "5569f1501147d3602287d9cae74af907e5be062cb90653c03d58cba12cac9db4")
	checkSHA256(t, "private key", private, "96bf4ccf9d963abe4609d845e0904eec999910b70d6b1fdfacfa8700ea9beaad")
	checkSHA256(t, "signature", signature, "874aca4adf12a73edb67521612928981e0931858030726ec0de028643803ed1a")
}

func testSeed() []byte {
	seed := make([]byte, SeedSize)
	countingReader(0).Read(seed)
	return seed
}

func mustNewKeyFromSeed(t testing.TB, seed []byte) (PublicKey, PrivateKey) {
	t.Helper()

	public, private, err := NewKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func checkSHA256(t *testing.T, name string, got []byte, want string) {
	t.Helper()

	sum := sha256.Sum256(got)
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("%s digest mismatch: got %s, want %s", name, got, want)
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	for b.Loop() {
		if _, _, err := GenerateKey(countingReader(0)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewKeyFromSeed(b *testing.B) {
	seed := testSeed()
	for b.Loop() {
		if _, _, err := NewKeyFromSeed(seed); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSigning(b *testing.B) {
	_, priv := mustNewKeyFromSeed(b, testSeed())
	message := []byte("Hello, world!")
	for b.Loop() {
		if _, err := Sign(countingReader(0), priv, message); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerification(b *testing.B) {
	pub, priv := mustNewKeyFromSeed(b, testSeed())
	message := []byte("Hello, world!")
	signature, err := Sign(countingReader(0), priv, message)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		Verify(pub, message, signature)
	}
}
