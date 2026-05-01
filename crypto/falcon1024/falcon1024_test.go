package falcon1024

import (
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

func TestGenerateKey(t *testing.T) {
	// nil is like using crypto/rand.Reader.
	public, private, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(public) != PublicKeySize {
		t.Errorf("public key has the wrong size: %d", len(public))
	}
	if len(private) != PrivateKeySize {
		t.Errorf("private key has the wrong size: %d", len(private))
	}

	/*
		cpublic, err := private.Public()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(cpublic.(PublicKey), public) {
			t.Errorf("public key doesn't match private key")
		}

		seed, err := private.Seed()
		if err != nil {
			t.Fatal(err)
		}
		_, fromSeed := NewKeyFromSeed(seed) // TODO: pubkey
		if !bytes.Equal(private, fromSeed) {
			t.Errorf("recreating key pair from seed gave different private key")
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
		rand.Read(seed)
		_, k4, err := GenerateKey(bytes.NewReader(seed))
		if err != nil {
			t.Fatal(err)
		}
		_, k4n := NewKeyFromSeed(seed) // TODO: pubkey
		if !bytes.Equal(k4, k4n) {
			t.Errorf("GenerateKey with seed gave different private key")
		}
	*/
}

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	clear(buf)
	return len(buf), nil
}

func TestSignVerify(t *testing.T) {
	var zero zeroReader
	public, private, _ := GenerateKey(zero)

	message := []byte("test message")
	sig := Sign(private, message)
	if !Verify(public, message, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if Verify(public, wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}
}

// TODO
/*
func TestGolden(t *testing.T) {
	// sign.input.gz is a selection of test cases from
	// https://ed25519.cr.yp.to/python/sign.input
	testDataZ, err := os.Open("testdata/sign.input.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer testDataZ.Close()
	testData, err := gzip.NewReader(testDataZ)
	if err != nil {
		t.Fatal(err)
	}
	defer testData.Close()

	scanner := bufio.NewScanner(testData)
	lineNo := 0

	for scanner.Scan() {
		lineNo++

		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) != 5 {
			t.Fatalf("bad number of parts on line %d", lineNo)
		}

		privBytes, _ := hex.DecodeString(parts[0])
		pubKey, _ := hex.DecodeString(parts[1])
		msg, _ := hex.DecodeString(parts[2])
		sig, _ := hex.DecodeString(parts[3])
		// The signatures in the test vectors also include the message
		// at the end, but we just want R and S.
		sig = sig[:SignatureSize]

		if l := len(pubKey); l != PublicKeySize {
			t.Fatalf("bad public key length on line %d: got %d bytes", lineNo, l)
		}

		var priv [PrivateKeySize]byte
		copy(priv[:], privBytes)
		copy(priv[32:], pubKey)

		sig2 := Sign(priv[:], msg)
		if !bytes.Equal(sig, sig2[:]) {
			t.Errorf("different signature result on line %d: %x vs %x", lineNo, sig, sig2)
		}

		if !Verify(pubKey, msg, sig2) {
			t.Errorf("signature failed to verify on line %d", lineNo)
		}

		pub2, priv2 := NewKeyFromSeed(priv[:32])
		if !bytes.Equal(priv[:], priv2) {
			t.Errorf("recreating key pair gave different private key on line %d: %x vs %x", lineNo, priv[:], priv2)
		}

		if pubKey2 := priv2.Public().(PublicKey); !bytes.Equal(pubKey, pubKey2) {
			t.Errorf("recreating key pair gave different public key on line %d: %x vs %x", lineNo, pubKey, pubKey2)
		}

		if seed := priv2.Seed(); !bytes.Equal(priv[:32], seed) {
			t.Errorf("recreating key pair gave different seed on line %d: %x vs %x", lineNo, priv[:32], seed)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("error reading test data: %s", err)
	}
}
*/

// TODO
/*
func TestAllocations(t *testing.T) {
	cryptotest.SkipTestAllocations(t)
	seed := make([]byte, SeedSize)
	pub, priv := NewKeyFromSeed(seed)
	if allocs := testing.AllocsPerRun(100, func() {
		message := []byte("Hello, world!")
		signature := Sign(priv, message)
		if !Verify(pub, message, signature) {
			t.Fatal("signature didn't verify")
		}
	}); allocs > 0 {
		t.Errorf("expected zero allocations, got %0.1f", allocs)
	}
}
*/

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
		_, _ = NewKeyFromSeed(seed)
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
		Sign(priv, message)
	}
}

func BenchmarkVerification(b *testing.B) {
	var zero zeroReader
	pub, priv, err := GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature := Sign(priv, message)
	for b.Loop() {
		Verify(pub, message, signature)
	}
}
