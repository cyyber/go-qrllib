package mlkem1024_test

import (
	"log"

	"github.com/theQRL/go-qrllib/crypto/mlkem1024"
)

func Example() {
	receiverDK, err := mlkem1024.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	receiverEK := receiverDK.EncapsulationKey().Bytes()

	senderEK, err := mlkem1024.NewEncapsulationKey(receiverEK)
	if err != nil {
		log.Fatal(err)
	}
	senderSharedKey, ciphertext, err := senderEK.Encapsulate()
	if err != nil {
		log.Fatal(err)
	}
	_ = senderSharedKey

	receiverSharedKey, err := receiverDK.Decapsulate(ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	_ = receiverSharedKey
}
