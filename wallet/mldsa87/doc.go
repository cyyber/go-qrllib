// Package mldsa87 provides a wallet implementation for ML-DSA-87 signatures
// on QRL V2.0.
//
// This package wraps the low-level [github.com/theQRL/go-qrllib/crypto/mldsa87]
// package and provides:
//
//   - QRL address generation with proper descriptor formatting
//   - Domain-separated signing context bound to the wallet descriptor
//   - Seed management and mnemonic conversion
//   - Signature verification with address descriptor validation
//
// # Context Handling
//
// The underlying ML-DSA-87 algorithm requires a context parameter for FIPS 204
// compliance. This wallet package constructs the context from the wallet's
// descriptor using [github.com/theQRL/go-qrllib/wallet/common.SigningContext]:
//
//	ctx = "ZOND" || SigningContextVersion || descriptor   (fixed 8 bytes)
//
// The descriptor (type byte + reserved metadata bytes) is embedded verbatim so
// the signature commits cryptographically to the signing wallet's descriptor
// and, by extension, to the address derived from it. A signature produced under
// descriptor D1 will not verify under any other descriptor D2. The version byte
// (currently 0x01) reserves room for a future redesign of the context layout;
// bumping it is a signature-format break and must coincide with a coordinated
// consensus activation.
//
// Callers do not supply the context themselves; it is computed automatically
// from the wallet's descriptor when signing, and from the descriptor parameter
// passed to [Verify]:
//
//	// Wallet layer - context is derived from the descriptor
//	wallet, _ := mldsa87.NewWallet()
//	signature, _ := wallet.Sign(nil, message)
//
//	// Crypto layer - context is an explicit option
//	_, signer, _ := cryptoMldsa87.GenerateKey(nil)
//	signature, _ := signer.Sign(nil, message, &cryptoMldsa87.Options{
//	    Context: common.SigningContext(desc),
//	})
//
// # Seed Derivation
//
// The wallet uses a 48-byte common seed that is hashed with SHA-256 to produce
// the 32-byte seed for ML-DSA-87 key generation:
//
//	Common Seed (48 bytes) → SHA-256 → ML-DSA-87 Seed (32 bytes) → Keypair
//
// # Signing Mode
//
// Wallet signing is hedged by default as per FIPS 204: each call to
// [Wallet.Sign] with nil randomness mixes fresh `crypto/rand` randomness into
// the per-signature `RND_BYTES`, so two signs over the same message produce
// distinct signature bytes, both of which verify under the wallet's public key
// and descriptor. Callers that need deterministic signatures can pass a
// deterministic reader. See the
// [github.com/theQRL/go-qrllib/crypto/mldsa87] package doc
// "Signing Mode" section for the full discussion.
//
// # Address Format
//
// QRL addresses are generated from the public key with a descriptor prefix using SHAKE256:
//
//	Address = "Q" + hex(SHAKE256(Descriptor || PK)[:64])
//
// This produces a standard 64-byte address (plus 'Q' prefix).
//
// # Example Usage
//
//	// Create a fresh wallet, or restore from a mnemonic / extended seed.
//	w, err := mldsa87.NewWallet()
//	// w, err := mldsa87.NewWalletFromMnemonic(phrase)
//	// w, err := mldsa87.NewWalletFromHexExtendedSeed(hexSeed)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer w.Zeroize()
//
//	address := w.GetAddressStr()              // "Q" + hex(64 bytes)
//	pk      := w.GetPK()
//	desc    := w.GetDescriptor().ToDescriptor()
//
//	sig, err := w.Sign(nil, message)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	ok := mldsa87.Verify(message, sig[:], &pk, desc)
//
// # Thread Safety
//
// A Wallet instance has the same thread safety characteristics as the underlying
// crypto/mldsa87 private-key type: safe for concurrent reads, but Sign should not be called
// concurrently on the same instance.
package mldsa87
