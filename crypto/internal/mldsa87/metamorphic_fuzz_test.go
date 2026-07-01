// Metamorphic fuzz tests for ML-DSA-87, contributed by Trail of Bits
// during the audit engagement (TOB-QRLLIB). Light adaptations applied
// for current go-qrllib API surface (post TOB-6 / TOB-12 / TOB-14):
//   - `Sign` is hedged-by-default; tests that assert "different message
//     → different signature" as a property of *deterministic* signing
//     route through [SignDeterministic] so the assertion is
//     genuinely testing the metamorphic property rather than trivially
//     observing per-call freshness.

package mldsa87

import (
	"bytes"
	"testing"
)

const (
	metamorphicFuzzMaxContextLen = 255
	metamorphicFuzzMaxMessageLen = 256
)

func metamorphicFuzzSeed(seedBytes []byte) [SEED_BYTES]uint8 {
	var seed [SEED_BYTES]uint8
	copy(seed[:], limitFuzzBytes(seedBytes, SEED_BYTES))
	return seed
}

func metamorphicMaulSingleBit(src []byte, bitIndex uint32) []byte {
	out := append([]byte(nil), src...)
	if len(out) == 0 {
		return []byte{1}
	}
	bit := int(bitIndex) % (len(out) * 8)
	out[bit/8] ^= 1 << (bit % 8)
	return out
}

func mustMetamorphicSigner(t *testing.T, seedBytes []byte) *PrivateKey {
	t.Helper()
	seed := metamorphicFuzzSeed(seedBytes)
	mldsa, err := NewPrivateKey(seed[:])
	if err != nil {
		t.Fatalf("NewPrivateKey failed: %v", err)
	}
	return mldsa
}

func fuzzableCtx(ctx []byte) []byte {
	return limitFuzzBytes(ctx, metamorphicFuzzMaxContextLen)
}

func fuzzableMsg(msg []byte) []byte {
	msg = limitFuzzBytes(msg, metamorphicFuzzMaxMessageLen)
	if len(msg) == 0 {
		return []byte{0}
	}
	return msg
}

func FuzzMetamorphicVerifyRejectsMauledPublicKey(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x00}, SEED_BYTES), []byte{}, []byte("message"), uint32(0))
	f.Add(bytes.Repeat([]byte{0xFF}, SEED_BYTES), bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte("m"), 64), uint32(17))

	f.Fuzz(func(t *testing.T, seedBytes, ctx, msg []byte, bitIndex uint32) {
		ctx = fuzzableCtx(ctx)
		msg = fuzzableMsg(msg)

		mldsa := mustMetamorphicSigner(t, seedBytes)
		sig, err := Sign(nil, mldsa, msg, ctx)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		pk := mldsa.PublicKey().raw
		if !verifyForTest(ctx, msg, sig, &pk) {
			t.Fatal("baseline signature failed verification")
		}

		mauledBytes := metamorphicMaulSingleBit(pk[:], bitIndex)
		var mauledPK [CRYPTO_PUBLIC_KEY_BYTES]uint8
		copy(mauledPK[:], mauledBytes)

		if verifyForTest(ctx, msg, sig, &mauledPK) {
			t.Fatalf("single-bit mauled public key verified (bitIndex=%d)", bitIndex)
		}
	})
}

func FuzzMetamorphicVerifyRejectsMauledMessage(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x00}, SEED_BYTES), []byte{}, []byte("message"), uint32(0))
	f.Add(bytes.Repeat([]byte{0xFF}, SEED_BYTES), bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte("m"), 64), uint32(17))

	f.Fuzz(func(t *testing.T, seedBytes, ctx, msg []byte, bitIndex uint32) {
		ctx = fuzzableCtx(ctx)
		msg = fuzzableMsg(msg)

		mldsa := mustMetamorphicSigner(t, seedBytes)
		sig, err := Sign(nil, mldsa, msg, ctx)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		pk := mldsa.PublicKey().raw
		if !verifyForTest(ctx, msg, sig, &pk) {
			t.Fatal("baseline signature failed verification")
		}

		mauledMsg := metamorphicMaulSingleBit(msg, bitIndex)
		if bytes.Equal(mauledMsg, msg) {
			t.Fatal("message maul did not change the input")
		}
		if verifyForTest(ctx, mauledMsg, sig, &pk) {
			t.Fatalf("single-bit mauled message verified (bitIndex=%d)", bitIndex)
		}
	})
}

func FuzzMetamorphicVerifyRejectsMauledSignature(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x00}, SEED_BYTES), []byte{}, []byte("message"), uint32(0))
	f.Add(bytes.Repeat([]byte{0xFF}, SEED_BYTES), bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte("m"), 64), uint32(17))

	f.Fuzz(func(t *testing.T, seedBytes, ctx, msg []byte, bitIndex uint32) {
		ctx = fuzzableCtx(ctx)
		msg = fuzzableMsg(msg)

		mldsa := mustMetamorphicSigner(t, seedBytes)
		sig, err := Sign(nil, mldsa, msg, ctx)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		pk := mldsa.PublicKey().raw
		if !verifyForTest(ctx, msg, sig, &pk) {
			t.Fatal("baseline signature failed verification")
		}

		mauledBytes := metamorphicMaulSingleBit(sig[:], bitIndex)
		var mauledSig [CRYPTO_BYTES]uint8
		copy(mauledSig[:], mauledBytes)

		if verifyForTest(ctx, msg, mauledSig[:], &pk) {
			t.Fatalf("single-bit mauled signature verified (bitIndex=%d)", bitIndex)
		}
	})
}

// FuzzMetamorphicDeterministicSigningChangesOnMauledMessage asserts the
// metamorphic property "same key, same ctx, different msg → different
// signature bytes" for deterministic signing. Under hedged signing this
// property holds trivially (every call uses fresh randomness so any two
// signs differ); routing through [SignDeterministic] makes the
// assertion genuinely test that the message *content* influences the
// signature bytes.
func FuzzMetamorphicDeterministicSigningChangesOnMauledMessage(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x00}, SEED_BYTES), []byte{}, []byte("message"), uint32(0))
	f.Add(bytes.Repeat([]byte{0xFF}, SEED_BYTES), bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte("m"), 64), uint32(17))

	f.Fuzz(func(t *testing.T, seedBytes, ctx, msg []byte, bitIndex uint32) {
		ctx = fuzzableCtx(ctx)
		msg = fuzzableMsg(msg)

		mldsa := mustMetamorphicSigner(t, seedBytes)
		baseSig, err := SignDeterministic(mldsa, msg, ctx)
		if err != nil {
			t.Fatalf("SignDeterministic failed: %v", err)
		}

		mauledMsg := metamorphicMaulSingleBit(msg, bitIndex)
		mauledSig, err := SignDeterministic(mldsa, mauledMsg, ctx)
		if err != nil {
			t.Fatalf("SignDeterministic on mauled message failed: %v", err)
		}

		if bytes.Equal(mauledSig, baseSig) {
			t.Fatalf("deterministic signing collision after single-bit message maul (bitIndex=%d)", bitIndex)
		}
	})
}
