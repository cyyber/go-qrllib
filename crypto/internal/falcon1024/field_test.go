package falcon1024

import (
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestHashToPointReferenceKATs(t *testing.T) {
	// The expected digests were derived from the Falcon reference
	// implementation hash_to_point_vartime applied to KAT_SIG_1024
	// nonce/message pairs. Digests are over 1024 big-endian uint16 values.
	// Source: https://falcon-sign.info/impl/test_falcon.c.html
	expected := []string{
		"e8332e46eeaa30a54945a14a405fcad8ef8078a87657e50e18248076bab9ecb7",
		"5c8070d70b241263cac562873abc120d7ab1534df58675fd14bf423a3112262a",
		"a8cbf92a0cc62556390ad065413dee950f64823129137b9a9a421eb41b9917b4",
		"c4f713a7bea9306abfcef6c9649ddd7f2e67ecfea8af0d6d1c05818f97175adb",
		"aa27dacdb980b409fbdd42c4677b44ba6fea7dcb7737278e70dd893e1d2e1c39",
		"979a62214e9f56d75c92e47f6dcaaf820142afac083d8e7f9a9c93c97431d214",
		"c9d0d5942821d2f3bf2b3a2357a20725494672390b8c4e44b7f23ac39ce5de45",
		"708ccbe5cb4fbd41e62b19e62d617766db64a72bebe69b86e011ee2bda6430b7",
		"c4ff487ff47d860298beffcf7f2cb5fcf3b3d3cf268ebe4361dd08c27b08fd9c",
		"bbeca2dd0710cdcaad7d573f4a137d93a30ee81f47f8287aa9ff4f7f84d6d039",
	}

	if len(expected) != len(verifyRawKATs) {
		t.Fatalf("expected digests = %d, verifyRawKATs = %d", len(expected), len(verifyRawKATs))
	}

	for i, tc := range verifyRawKATs {
		t.Run(tc.message, func(t *testing.T) {
			h := sha3.NewSHAKE256()
			_, _ = h.Write(mustDecodeHex(t, tc.nonceHex))
			_, _ = h.Write([]byte(tc.message))

			p := hashToPoint(h)

			var b [2 * n]byte
			for j, x := range p {
				binary.BigEndian.PutUint16(b[2*j:], uint16(x))
			}
			digest := sha256.Sum256(b[:])
			if got := hex.EncodeToString(digest[:]); got != expected[i] {
				t.Fatalf("hashToPoint digest = %s, want %s", got, expected[i])
			}
		})
	}
}
