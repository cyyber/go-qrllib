package mldsa87_test

import (
	"log"

	"github.com/theQRL/go-qrllib/crypto/mldsa87"
)

func Example() {
	pub, priv, err := mldsa87.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("hello, world")

	sig, err := priv.Sign(nil, msg, nil)
	if err != nil {
		log.Fatal(err)
	}

	if ok := mldsa87.Verify(pub, msg, sig, nil); !ok {
		log.Fatal("invalid signature")
	}
}

func Example_withContext() {
	pub, priv, err := mldsa87.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("hello, world")
	opts := &mldsa87.Options{Context: []byte("example-context")}

	sig, err := priv.Sign(nil, msg, opts)
	if err != nil {
		log.Fatal(err)
	}

	if ok := mldsa87.Verify(pub, msg, sig, opts); !ok {
		log.Fatal("invalid signature")
	}
}
