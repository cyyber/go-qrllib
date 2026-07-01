package mldsa87

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Edge case tests for ML-DSA-87 (TST-004)
// Tests cover: zero-length messages, maximum-length messages,
// invalid signatures, and boundary conditions.

// TestEdgeCaseZeroLengthMessage tests signing and verifying empty messages
func TestEdgeCaseZeroLengthMessage(t *testing.T) {
	mldsa, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create PrivateKey: %v", err)
	}

	emptyMsg := []byte{}
	ctx := []byte{}

	// Sign empty message
	sig, err := Sign(nil, mldsa, emptyMsg, ctx)
	if err != nil {
		t.Fatalf("Failed to sign empty message: %v", err)
	}

	// Verify empty message
	pk := mldsa.PublicKey().raw
	if !verifyForTest(ctx, emptyMsg, sig, &pk) {
		t.Error("Failed to verify signature on empty message")
	}

}

// TestEdgeCaseNilMessage tests handling of nil messages
func TestEdgeCaseNilMessage(t *testing.T) {
	mldsa, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create PrivateKey: %v", err)
	}

	var nilMsg []byte = nil
	ctx := []byte{}

	// Sign nil message (should behave like empty)
	sig, err := Sign(nil, mldsa, nilMsg, ctx)
	if err != nil {
		t.Fatalf("Failed to sign nil message: %v", err)
	}

	// Verify nil message
	pk := mldsa.PublicKey().raw
	if !verifyForTest(ctx, nilMsg, sig, &pk) {
		t.Error("Failed to verify signature on nil message")
	}
}

// TestEdgeCaseLargeMessage tests signing large messages
func TestEdgeCaseLargeMessage(t *testing.T) {
	mldsa, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create PrivateKey: %v", err)
	}

	// Test various large message sizes
	sizes := []int{
		1024,        // 1 KB
		64 * 1024,   // 64 KB
		1024 * 1024, // 1 MB
	}

	for _, size := range sizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			largeMsg := make([]byte, size)
			if _, err := rand.Read(largeMsg); err != nil {
				t.Fatalf("Failed to generate random message: %v", err)
			}

			ctx := []byte{}

			sig, err := Sign(nil, mldsa, largeMsg, ctx)
			if err != nil {
				t.Fatalf("Failed to sign %d byte message: %v", size, err)
			}

			pk := mldsa.PublicKey().raw
			if !verifyForTest(ctx, largeMsg, sig, &pk) {
				t.Errorf("Failed to verify signature on %d byte message", size)
			}
		})
	}
}

// TestEdgeCaseInvalidSignature tests various invalid signature scenarios
func TestEdgeCaseInvalidSignature(t *testing.T) {
	mldsa, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create PrivateKey: %v", err)
	}

	msg := []byte("test message")
	ctx := []byte{}
	pk := mldsa.PublicKey().raw

	t.Run("all_zeros_signature", func(t *testing.T) {
		var zeroSig [CRYPTO_BYTES]uint8
		if verifyForTest(ctx, msg, zeroSig[:], &pk) {
			t.Error("All-zeros signature should not verify")
		}
	})

	t.Run("all_ones_signature", func(t *testing.T) {
		var onesSig [CRYPTO_BYTES]uint8
		for i := range onesSig {
			onesSig[i] = 0xFF
		}
		if verifyForTest(ctx, msg, onesSig[:], &pk) {
			t.Error("All-ones signature should not verify")
		}
	})

	t.Run("random_signature", func(t *testing.T) {
		var randomSig [CRYPTO_BYTES]uint8
		_, _ = rand.Read(randomSig[:])
		if verifyForTest(ctx, msg, randomSig[:], &pk) {
			t.Error("Random signature should not verify")
		}
	})

	t.Run("corrupted_valid_signature", func(t *testing.T) {
		sig, err := Sign(nil, mldsa, msg, ctx)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		// Corrupt each byte position
		for i := 0; i < len(sig); i += len(sig) / 10 { // Test every 10%
			corruptedSig := sig
			corruptedSig[i] ^= 0xFF
			if verifyForTest(ctx, msg, corruptedSig, &pk) {
				t.Errorf("Corrupted signature at byte %d should not verify", i)
			}
		}
	})
}

// TestEdgeCaseMalformedSignatureHints tests signature hint encoding validation
func TestEdgeCaseMalformedSignatureHints(t *testing.T) {
	mldsa, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create PrivateKey: %v", err)
	}

	msg := []byte("test message")
	ctx := []byte{}
	pk := mldsa.PublicKey().raw

	// Get a valid signature to use as base
	validSig, err := Sign(nil, mldsa, msg, ctx)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Signature layout: c_tilde (64) || z (L*640=4480) || hints (OMEGA+K=83)
	// Hints layout: hint_indices[OMEGA] || cumulative_counts[K]
	hintStart := C_TILDE_BYTES + L*POLY_Z_PACKED_BYTES // 64 + 4480 = 4544

	t.Run("non_increasing_hint_indices", func(t *testing.T) {
		// Create a signature with non-increasing hint indices
		malformedSig := validSig
		// Set hint indices that are not strictly increasing
		// First, set cumulative count to indicate we have 2 hints in first polynomial
		malformedSig[hintStart+OMEGA] = 2 // cumulative count for poly 0
		// Set hint indices: second should be > first, but we make it equal
		malformedSig[hintStart+0] = 10
		malformedSig[hintStart+1] = 10 // Not strictly increasing!

		if verifyForTest(ctx, msg, malformedSig, &pk) {
			t.Error("Signature with non-increasing hint indices should not verify")
		}
	})

	t.Run("decreasing_hint_indices", func(t *testing.T) {
		malformedSig := validSig
		malformedSig[hintStart+OMEGA] = 2
		malformedSig[hintStart+0] = 20
		malformedSig[hintStart+1] = 10 // Decreasing!

		if verifyForTest(ctx, msg, malformedSig, &pk) {
			t.Error("Signature with decreasing hint indices should not verify")
		}
	})

	t.Run("non_zero_padding_in_hints", func(t *testing.T) {
		malformedSig := validSig
		// Set all cumulative counts to 0 (no hints)
		for i := range K {
			malformedSig[hintStart+OMEGA+i] = 0
		}
		// But put non-zero data in the hint indices area
		malformedSig[hintStart+0] = 0xFF // Should be zero if no hints

		if verifyForTest(ctx, msg, malformedSig, &pk) {
			t.Error("Signature with non-zero hint padding should not verify")
		}
	})
}

// TestEdgeCaseInvalidPublicKey tests verification with invalid public keys
func TestEdgeCaseInvalidPublicKey(t *testing.T) {
	mldsa, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create PrivateKey: %v", err)
	}

	msg := []byte("test message")
	ctx := []byte{}
	sig, err := Sign(nil, mldsa, msg, ctx)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	t.Run("all_zeros_pk", func(t *testing.T) {
		var zeroPK [CRYPTO_PUBLIC_KEY_BYTES]uint8
		if verifyForTest(ctx, msg, sig, &zeroPK) {
			t.Error("All-zeros public key should not verify")
		}
	})

	t.Run("random_pk", func(t *testing.T) {
		var randomPK [CRYPTO_PUBLIC_KEY_BYTES]uint8
		_, _ = rand.Read(randomPK[:])
		if verifyForTest(ctx, msg, sig, &randomPK) {
			t.Error("Random public key should not verify")
		}
	})
}

// TestEdgeCaseContextVariations tests various context scenarios
func TestEdgeCaseContextVariations(t *testing.T) {
	mldsa, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create PrivateKey: %v", err)
	}

	msg := []byte("test message")
	pk := mldsa.PublicKey().raw

	contexts := [][]byte{
		nil,
		{},
		{0x00},
		[]byte("short"),
		[]byte("a longer context string for testing"),
		bytes.Repeat([]byte{0x42}, 255), // Max context length per FIPS 204
	}

	for i, ctx := range contexts {
		t.Run(string(rune(i)), func(t *testing.T) {
			sig, err := Sign(nil, mldsa, msg, ctx)
			if err != nil {
				t.Fatalf("Failed to sign with context %d: %v", i, err)
			}

			if !verifyForTest(ctx, msg, sig, &pk) {
				t.Errorf("Failed to verify with context %d", i)
			}

			// Verify with wrong context should fail
			wrongCtx := append(ctx, 0xFF)
			if verifyForTest(wrongCtx, msg, sig, &pk) {
				t.Errorf("Verification should fail with wrong context %d", i)
			}
		})
	}

	// Test context exceeding max length (256 bytes, exceeds 255 limit per FIPS 204)
	t.Run("context_too_long", func(t *testing.T) {
		longCtx := bytes.Repeat([]byte{0x42}, 256)
		_, err := Sign(nil, mldsa, msg, longCtx)
		if err == nil {
			t.Error("Sign should fail with context > 255 bytes")
		}

	})
}

// TestEdgeCaseSeedBoundaries tests seed handling edge cases
func TestEdgeCaseSeedBoundaries(t *testing.T) {
	t.Run("zero_seed", func(t *testing.T) {
		var zeroSeed [SEED_BYTES]uint8
		mldsa, err := NewPrivateKey(zeroSeed[:])
		if err != nil {
			t.Fatalf("Failed to create from zero seed: %v", err)
		}

		msg := []byte("test")
		ctx := []byte{}
		sig, err := Sign(nil, mldsa, msg, ctx)
		if err != nil {
			t.Fatalf("Failed to sign with zero seed: %v", err)
		}

		pk := mldsa.PublicKey().raw
		if !verifyForTest(ctx, msg, sig, &pk) {
			t.Error("Failed to verify with zero seed keypair")
		}
	})

	t.Run("max_seed", func(t *testing.T) {
		var maxSeed [SEED_BYTES]uint8
		for i := range maxSeed {
			maxSeed[i] = 0xFF
		}
		mldsa, err := NewPrivateKey(maxSeed[:])
		if err != nil {
			t.Fatalf("Failed to create from max seed: %v", err)
		}

		msg := []byte("test")
		ctx := []byte{}
		sig, err := Sign(nil, mldsa, msg, ctx)
		if err != nil {
			t.Fatalf("Failed to sign with max seed: %v", err)
		}

		pk := mldsa.PublicKey().raw
		if !verifyForTest(ctx, msg, sig, &pk) {
			t.Error("Failed to verify with max seed keypair")
		}
	})
}

// fixtureSign produces a real signature so tests have well-formed material to
// feed into Verify. Using real material rules out "Verify returned false
// because the signature was malformed" as an alternative explanation when
// asserting the nil-pk refusal path.
func fixtureSign(t *testing.T) (msg []byte, ctx []byte, sig [CRYPTO_BYTES]uint8) {
	t.Helper()
	mldsa, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("setup: New failed: %v", err)
	}
	msg = []byte("nil-pk regression test message")
	ctx = []byte("test-ctx")
	sigBytes, err := Sign(nil, mldsa, msg, ctx)
	if err != nil {
		t.Fatalf("setup: Sign failed: %v", err)
	}
	copy(sig[:], sigBytes)
	return msg, ctx, sig
}

func TestVerify_NilPublicKey_ReturnsErrorNoPanic(t *testing.T) {
	msg, ctx, sig := fixtureSign(t)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Verify panicked on nil public key: %v", r)
		}
	}()

	if err := Verify(nil, msg, sig[:], ctx); err == nil || err.Error() != "mldsa87: public key is nil" {
		t.Fatalf("Verify(nil pk) err = %v; want mldsa87: public key is nil", err)
	}
}

func TestCryptoSignVerify_NilPublicKey_ReturnsErrPublicKeyNil(t *testing.T) {
	msg, ctx, sig := fixtureSign(t)

	ok, err := cryptoSignVerify(sig, msg, ctx, nil)
	if ok {
		t.Error("cryptoSignVerify(nil pk) returned ok=true; want false")
	}
	if err == nil || err.Error() != "mldsa87: public key is nil" {
		t.Errorf("cryptoSignVerify(nil pk) err = %v; want mldsa87: public key is nil", err)
	}
}
