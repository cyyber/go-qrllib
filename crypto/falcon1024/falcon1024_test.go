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
