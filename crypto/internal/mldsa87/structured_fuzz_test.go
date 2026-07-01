// Structured fuzz tests for ML-DSA-87, contributed by Trail of Bits
// during the audit engagement (TOB-QRLLIB). Light adaptations applied
// for current go-qrllib API surface (post TOB-6 / TOB-12 / TOB-14):
//   - the `randomized bool` parameter was removed from
//     `cryptoSignSignature` (hedged is now the default)

package mldsa87

import (
	"bytes"
	"testing"
)

const (
	fuzzMaxContextLen  = 256
	fuzzMaxMessageLen  = 4096
	fuzzMaxMutationLen = 64
)

func limitFuzzBytes(b []byte, max int) []byte {
	if len(b) > max {
		return b[:max]
	}
	return b
}

func fuzzSeed32(seedBytes []byte) [SEED_BYTES]uint8 {
	var seed [SEED_BYTES]uint8
	copy(seed[:], limitFuzzBytes(seedBytes, SEED_BYTES))
	return seed
}

func mutateSlice(base []byte, mutation []byte) []byte {
	out := append([]byte(nil), base...)
	if len(out) == 0 {
		if len(mutation) == 0 {
			return []byte{1}
		}
		return []byte{mutation[0] ^ 0x01}
	}

	idx := 0
	mask := byte(0x01)
	if len(mutation) > 0 {
		idx = int(mutation[0]) % len(out)
	}
	if len(mutation) > 1 {
		mask = mutation[1]
		if mask == 0 {
			mask = 0x01
		}
	}

	out[idx] ^= mask
	return out
}

func mutateSignature(sig []byte, mutation []byte) []byte {
	mutated := append([]byte(nil), sig...)
	idx := 0
	mask := byte(0x01)
	if len(mutation) > 0 {
		idx = int(mutation[0]) % len(mutated)
	}
	if len(mutation) > 1 {
		mask = mutation[1]
		if mask == 0 {
			mask = 0x01
		}
	}
	mutated[idx] ^= mask
	return mutated
}

func mutatePublicKey(pk [CRYPTO_PUBLIC_KEY_BYTES]uint8, mutation []byte) [CRYPTO_PUBLIC_KEY_BYTES]uint8 {
	mutated := pk
	idx := 0
	mask := byte(0x01)
	if len(mutation) > 0 {
		idx = int(mutation[0]) % len(mutated)
	}
	if len(mutation) > 1 {
		mask = mutation[1]
		if mask == 0 {
			mask = 0x01
		}
	}
	mutated[idx] ^= mask
	return mutated
}

func FuzzPrivateKeySignVerifyRoundTripMutate(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x00}, SEED_BYTES), []byte("ctx"), []byte("message"), []byte{0, 1})
	f.Add(bytes.Repeat([]byte{0xFF}, SEED_BYTES), bytes.Repeat([]byte{0x41}, 255), []byte{}, []byte{17, 0x80})
	f.Add([]byte("seed"), bytes.Repeat([]byte{0x42}, 256), bytes.Repeat([]byte("m"), 128), []byte{3, 7})

	f.Fuzz(func(t *testing.T, seedBytes, ctx, message, mutation []byte) {
		ctx = limitFuzzBytes(ctx, fuzzMaxContextLen)
		message = limitFuzzBytes(message, fuzzMaxMessageLen)
		mutation = limitFuzzBytes(mutation, fuzzMaxMutationLen)

		seed := fuzzSeed32(seedBytes)
		mldsa, err := NewPrivateKey(seed[:])
		if err != nil {
			t.Fatalf("NewPrivateKey failed: %v", err)
		}

		sig, err := Sign(nil, mldsa, message, ctx)
		if len(ctx) > 255 {
			if err == nil {
				t.Fatal("Sign succeeded with oversized context")
			}
			return
		}
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		pk := mldsa.PublicKey().raw
		if !verifyForTest(ctx, message, sig, &pk) {
			t.Fatal("Valid signature failed verification")
		}

		mutatedCtx := mutateSlice(ctx, mutation)
		if bytes.Equal(mutatedCtx, ctx) {
			t.Fatal("Context mutation did not change the input")
		}
		if verifyForTest(mutatedCtx, message, sig, &pk) {
			t.Fatal("Signature verified with mutated context")
		}

		mutatedMsg := mutateSlice(message, mutation)
		if bytes.Equal(mutatedMsg, message) {
			t.Fatal("Message mutation did not change the input")
		}
		if verifyForTest(ctx, mutatedMsg, sig, &pk) {
			t.Fatal("Signature verified with mutated message")
		}

		mutatedSig := mutateSignature(sig, mutation)
		if verifyForTest(ctx, message, mutatedSig, &pk) {
			t.Fatal("Mutated signature verified")
		}

		mutatedPK := mutatePublicKey(pk, mutation)
		if verifyForTest(ctx, message, sig, &mutatedPK) {
			t.Fatal("Signature verified with mutated public key")
		}
	})
}

func FuzzPrivateKeyFromSeedSignVerify(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x00}, SEED_BYTES), []byte("ctx"), []byte("digest"))
	f.Add(bytes.Repeat([]byte{0xFF}, SEED_BYTES), bytes.Repeat([]byte{0x41}, 255), []byte{})
	f.Add([]byte("seed"), bytes.Repeat([]byte{0x42}, 256), bytes.Repeat([]byte("d"), 128))

	f.Fuzz(func(t *testing.T, seedBytes, ctx, digest []byte) {
		ctx = limitFuzzBytes(ctx, fuzzMaxContextLen)
		digest = limitFuzzBytes(digest, fuzzMaxMessageLen)

		seed := fuzzSeed32(seedBytes)
		mldsa, err := NewPrivateKey(seed[:])
		if err != nil {
			t.Fatalf("NewPrivateKey failed: %v", err)
		}

		roundTrip, err := NewPrivateKey(mldsa.Bytes())
		if err != nil {
			t.Fatalf("Round-trip seed failed: %v", err)
		}
		if mldsa.PublicKey().raw != roundTrip.PublicKey().raw {
			t.Fatal("Seed round-trip changed the derived public key")
		}

		sig, err := Sign(nil, mldsa, digest, ctx)
		if len(ctx) > 255 {
			if err == nil {
				t.Fatal("Sign succeeded with oversized context")
			}
			return
		}
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		pk := mldsa.PublicKey().raw
		if !verifyForTest(ctx, digest, sig, &pk) {
			t.Fatal("Sign produced a signature that does not verify")
		}
	})
}

// FuzzPrivateKeyVerify tests that Verify handles arbitrary input without panicking.
func FuzzPrivateKeyVerify(f *testing.F) {
	// Add seed corpus with various sizes.
	f.Add(make([]byte, 0), make([]byte, 0), make([]byte, CRYPTO_BYTES), make([]byte, CRYPTO_PUBLIC_KEY_BYTES))
	f.Add(make([]byte, 10), make([]byte, 32), make([]byte, CRYPTO_BYTES), make([]byte, CRYPTO_PUBLIC_KEY_BYTES))
	f.Add(make([]byte, 255), make([]byte, 1000), make([]byte, CRYPTO_BYTES), make([]byte, CRYPTO_PUBLIC_KEY_BYTES))

	f.Fuzz(func(t *testing.T, ctx, message, sigBytes, pkBytes []byte) {
		var sig [CRYPTO_BYTES]uint8
		var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8

		copy(sig[:], sigBytes)
		copy(pk[:], pkBytes)

		_ = verifyForTest(ctx, message, sig[:], &pk)
	})
}
