package falcon1024_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/falcon1024"
)

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	clear(buf)
	return len(buf), nil
}

func TestGenerateKey(t *testing.T) {
	var zero zeroReader
	public, private, err := falcon1024.GenerateKey(zero)
	if err != nil {
		t.Fatal(err)
	}

	if len(public.Bytes()) != falcon1024.PublicKeySize {
		t.Fatalf("public key has wrong size: got %d, want %d", len(public.Bytes()), falcon1024.PublicKeySize)
	}
	if len(private.Bytes()) != falcon1024.PrivateKeySize {
		t.Fatalf("private key has wrong size: got %d, want %d", len(private.Bytes()), falcon1024.PrivateKeySize)
	}
	cpublic := private.Public()
	if !bytes.Equal(cpublic.(*falcon1024.PublicKey).Bytes(), public.Bytes()) {
		t.Fatal("private key returned unexpected public key")
	}

	seed := make([]byte, falcon1024.SeedSize)
	_, _ = zero.Read(seed)
	privateFromSeed, err := falcon1024.NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	publicFromSeed := privateFromSeed.Public().(*falcon1024.PublicKey)
	if !bytes.Equal(publicFromSeed.Bytes(), public.Bytes()) {
		t.Fatal("GenerateKey and NewPrivateKey returned different public keys")
	}
	if !bytes.Equal(privateFromSeed.Bytes(), private.Bytes()) {
		t.Fatal("GenerateKey and NewPrivateKey returned different private keys")
	}

	_, k2, err := falcon1024.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(private.Bytes(), k2.Bytes()) {
		t.Errorf("GenerateKey returned the same private key twice")
	}

	_, k3, err := falcon1024.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(private.Bytes(), k3.Bytes()) {
		t.Errorf("GenerateKey returned the same private key twice")
	}

	// GenerateKey reads a seed and expands it in the same way as NewPrivateKey.
	seed = make([]byte, falcon1024.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	_, k4, err := falcon1024.GenerateKey(bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	k4n, err := falcon1024.NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k4.Bytes(), k4n.Bytes()) {
		t.Errorf("GenerateKey with seed gave different private key")
	}
}

func TestSignVerify(t *testing.T) {
	var zero zeroReader
	public, private, err := falcon1024.GenerateKey(zero)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("test message")
	sig, err := falcon1024.Sign(zero, private, message)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != falcon1024.SignatureSize {
		t.Fatalf("signature has wrong size: got %d, want %d", len(sig), falcon1024.SignatureSize)
	}
	if !falcon1024.Verify(public, message, sig) {
		t.Fatal("valid signature rejected")
	}
	if falcon1024.Verify(public, []byte("wrong message"), sig) {
		t.Fatal("signature of different message accepted")
	}

	sig[falcon1024.SignatureSize-1] ^= 1
	if falcon1024.Verify(public, message, sig) {
		t.Fatal("modified signature accepted")
	}
}

func TestPrivateKeySign(t *testing.T) {
	var zero zeroReader
	public, private, err := falcon1024.GenerateKey(zero)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("PrivateKey.Sign message")

	sig, err := private.Sign(zero, message)
	if err != nil {
		t.Fatal(err)
	}
	if !falcon1024.Verify(public, message, sig) {
		t.Fatal("PrivateKey.Sign signature rejected")
	}
}

func TestNewPrivateKeyInvalidSeed(t *testing.T) {
	for _, seed := range [][]byte{
		nil,
		make([]byte, falcon1024.SeedSize-1),
		make([]byte, falcon1024.SeedSize+1),
	} {
		if _, err := falcon1024.NewPrivateKey(seed); err == nil {
			t.Fatalf("NewPrivateKey accepted seed with length %d", len(seed))
		}
	}
}

func TestVerifyInvalidInputs(t *testing.T) {
	var zero zeroReader
	public, private, err := falcon1024.GenerateKey(zero)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("test message")
	signature, err := falcon1024.Sign(zero, private, message)
	if err != nil {
		t.Fatal(err)
	}

	badHeaderPublic := bytes.Clone(public.Bytes())
	badHeaderPublic[0] ^= 0xFF

	for _, publicKey := range [][]byte{
		nil,
		make([]byte, falcon1024.PublicKeySize-1),
		make([]byte, falcon1024.PublicKeySize+1),
		badHeaderPublic,
	} {
		if _, err := falcon1024.NewPublicKey(publicKey); err == nil {
			t.Fatalf("NewPublicKey accepted invalid public key with length %d", len(publicKey))
		}
	}

	for _, tc := range []struct {
		name      string
		signature []byte
	}{
		{
			name:      "nil signature",
			signature: nil,
		},
		{
			name:      "short signature",
			signature: make([]byte, falcon1024.SignatureSize-1),
		},
		{
			name:      "long signature",
			signature: make([]byte, falcon1024.SignatureSize+1),
		},
		{
			name:      "wrong signature header",
			signature: append([]byte{signature[0] ^ 0xFF}, signature[1:]...),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if falcon1024.Verify(public, message, tc.signature) {
				t.Fatal("Verify accepted invalid input")
			}
		})
	}

	if !falcon1024.Verify(public, message, signature) {
		t.Fatal("Verify rejected valid input")
	}
}

func TestEqual(t *testing.T) {
	public, private, err := falcon1024.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if !public.Equal(public) {
		t.Errorf("public key is not equal to itself: %x", public.Bytes())
	}
	derivedPublic := private.Public()
	if !public.Equal(derivedPublic) {
		t.Errorf("private.Public() is not Equal to public: %x", public.Bytes())
	}
	if !private.Equal(private) {
		t.Errorf("private key is not equal to itself: %x", private.Bytes())
	}

	otherPub, otherPriv, err := falcon1024.GenerateKey(rand.Reader)
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
	public, private, err := falcon1024.GenerateKey(zero)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("Falcon-1024 public API golden test")
	signature, err := falcon1024.Sign(zero, private, message)
	if err != nil {
		t.Fatal(err)
	}
	if !falcon1024.Verify(public, message, signature) {
		t.Fatal("golden signature failed verification")
	}

	checkSHA256(t, "public key", public.Bytes(), "e6002a1133c82aa79254740e864960db9724b3f042ea8798d14cabddb8ef56be")
	checkSHA256(t, "private key", private.Bytes(), "17b0761f87b081d5cf10757ccc89f12be355c70e2e29df288b65b30710dcbcd1")
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
		if _, _, err := falcon1024.GenerateKey(zero); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewPrivateKey(b *testing.B) {
	seed := make([]byte, falcon1024.SeedSize)
	for b.Loop() {
		_, err := falcon1024.NewPrivateKey(seed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSigning(b *testing.B) {
	var zero zeroReader
	_, priv, err := falcon1024.GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	for b.Loop() {
		_, err := falcon1024.Sign(zero, priv, message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerification(b *testing.B) {
	var zero zeroReader
	pub, priv, err := falcon1024.GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature, err := falcon1024.Sign(zero, priv, message)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if !falcon1024.Verify(pub, message, signature) {
			b.Fatal("signature rejected")
		}
	}
}
