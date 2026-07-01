package mldsa87

import (
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"errors"
	"io"
	"runtime"
	"sync"
)

// shake256Pool provides pooled SHAKE256 hashers to reduce allocations
// in high-frequency signing and verification operations.
var shake256Pool = sync.Pool{
	New: func() any {
		return sha3.NewSHAKE256()
	},
}

// getShake256 returns a clean, reset SHAKE256 hasher from the pool.
func getShake256() *sha3.SHAKE {
	h := shake256Pool.Get().(*sha3.SHAKE)
	h.Reset()
	return h
}

// putShake256 resets a SHAKE256 hasher and returns it to the pool.
//
// The Reset is a security measure: the signing path absorbs secret key
// material through pooled states, and without a wipe-on-put that
// secret-derived sponge state would linger in the pool indefinitely.
// getShake256's Reset-on-Get is kept as defence-in-depth.
func putShake256(h *sha3.SHAKE) {
	h.Reset()
	shake256Pool.Put(h)
}

// zeroBytes overwrites b with zeros. runtime.KeepAlive prevents the compiler
// from eliding the writes as a dead store.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(&b)
}

func zeroPoly(p *poly) {
	for i := range p.coeffs {
		p.coeffs[i] = 0
	}
	runtime.KeepAlive(p)
}

func zeroPolyVecL(v *polyVecL) {
	for i := range v.vec {
		zeroPoly(&v.vec[i])
	}
}

func zeroPolyVecK(v *polyVecK) {
	for i := range v.vec {
		zeroPoly(&v.vec[i])
	}
}

// Take a random seed, and compute sk/pk pair.
func cryptoSignKeypair(seed *[SEED_BYTES]uint8, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8, sk *[CRYPTO_SECRET_KEY_BYTES]uint8, priv *PrivateKey, pub *PublicKey) (*[SEED_BYTES]uint8, error) {
	var tr [TR_BYTES]uint8
	var rho, key [SEED_BYTES]uint8
	var rhoPrime [CRH_BYTES]uint8

	var mat [K]polyVecL
	var s1, s1hat polyVecL
	var s2, t1, t0 polyVecK

	// Zeroize secret intermediates when key generation completes.
	// Mirrors the cleanup pattern in cryptoSignSignatureInternal so both
	// paths handle their unpacked secret material consistently. Go's GC
	// may copy values before zeroization executes, so this is a
	// best-effort reduction of the in-memory exposure window rather than
	// a guarantee — see SECURITY.md and PrivateKey.Zeroize for the exact
	// boundary. (TOB-QRLLIB-10)
	defer func() {
		zeroBytes(key[:])
		zeroBytes(rhoPrime[:])
		zeroPolyVecL(&s1)
		zeroPolyVecL(&s1hat)
		zeroPolyVecK(&s2)
		zeroPolyVecK(&t0)
	}()

	if seed == nil {
		//coverage:ignore
		//rationale: all public API callers (GenerateKey, NewPrivateKey) always provide a seed
		seed = new([SEED_BYTES]uint8)
		_, err := rand.Read(seed[:])
		if err != nil {
			//coverage:ignore
			//rationale: crypto/rand.Read only fails if system entropy source is broken
			return nil, errors.New("mldsa87: seed generation failed")
		}
	}
	/* Expand 32 bytes of randomness into rho, rhoprime and key */
	state := getShake256()
	defer putShake256(state)
	if _, err := state.Write(seed[:]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return nil, err
	}
	extraData := []byte{K, L}
	if _, err := state.Write(extraData); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return nil, err
	}
	if _, err := state.Read(rho[:]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		return nil, err
	}
	if _, err := state.Read(rhoPrime[:]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		return nil, err
	}
	if _, err := state.Read(key[:]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		return nil, err
	}

	/* Expand matrix */
	if err := polyVecMatrixExpand(&mat, &rho); err != nil {
		//coverage:ignore
		//rationale: polyVecMatrixExpand's sha3 operations never return errors
		return nil, err
	}

	/* Sample short vectors s1 and s2 */
	if err := polyVecLUniformETA(&s1, &rhoPrime, 0); err != nil {
		//coverage:ignore
		//rationale: polyVecLUniformETA's sha3 operations never return errors
		return nil, err
	}
	if err := polyVecKUniformETA(&s2, &rhoPrime, L); err != nil {
		//coverage:ignore
		//rationale: polyVecKUniformETA's sha3 operations never return errors
		return nil, err
	}

	/* Matrix-vector multiplication */
	s1hat = s1
	polyVecLNTT(&s1hat)
	polyVecMatrixPointWiseMontgomery(&t1, &mat, &s1hat)
	polyVecKReduce(&t1)
	polyVecKInvNTTToMont(&t1)

	/* Add noise vector s2 */
	polyVecKAdd(&t1, &t1, &s2)

	/* Extract t1 and write public key */
	polyVecKCAddQ(&t1)
	polyVecKPower2Round(&t1, &t0, &t1)
	packPk(pk, rho, &t1)

	/* Compute tr = CRH(rho, t1) and write secret key */
	copy(tr[:], sha3.SumSHAKE256(pk[:], TR_BYTES))
	packSk(sk, rho, tr, key, &t0, &s1, &s2)

	if priv != nil {
		priv.tr = tr
		priv.key = key
		priv.s1 = s1hat
		priv.s2 = s2
		polyVecKNTT(&priv.s2)
		priv.t0 = t0
		polyVecKNTT(&priv.t0)
	}
	if pub != nil {
		pub.raw = *pk
		pub.tr = tr
		pub.mat = mat
		pub.t1 = t1
		polyVecKShiftL(&pub.t1)
		polyVecKNTT(&pub.t1)
	}

	return seed, nil
}

func privateKeyFromSecretKey(sk *[CRYPTO_SECRET_KEY_BYTES]uint8) (*PrivateKey, [K]polyVecL, error) {
	var rho [SEED_BYTES]uint8
	var mat [K]polyVecL

	if sk == nil {
		return nil, mat, errPrivateKeyNil
	}
	priv := new(PrivateKey)
	unpackSk(&rho, &priv.tr, &priv.key, &priv.t0, &priv.s1, &priv.s2, sk)
	if err := polyVecMatrixExpand(&mat, &rho); err != nil {
		//coverage:ignore
		//rationale: polyVecMatrixExpand's sha3 operations never return errors
		priv.Zeroize()
		return nil, mat, err
	}
	polyVecLNTT(&priv.s1)
	polyVecKNTT(&priv.s2)
	polyVecKNTT(&priv.t0)
	return priv, mat, nil
}

func cryptoSignSignatureInternal(sig, m []uint8, pre []uint8, rnd [RND_BYTES]uint8, priv *PrivateKey, mat *[K]polyVecL) error {
	if priv == nil || mat == nil {
		return errPrivateKeyNil
	}
	var mu, rhoPrime [CRH_BYTES]uint8
	var y, z polyVecL
	var w1, h, w0 polyVecK
	var cp poly
	var nonce uint16

	// Zeroize secret temporaries when signing completes.
	// Go's GC may copy values before zeroization, but this still reduces
	// the window for secrets persisting in freed memory.
	defer func() {
		zeroBytes(rhoPrime[:])
	}()

	/* Compute mu = CRH(tr, 0, ctxlen, ctx, msg) */
	state := getShake256()
	defer putShake256(state)
	_, _ = state.Write(priv.tr[:])
	_, _ = state.Write(pre)
	_, _ = state.Write(m)
	_, _ = state.Read(mu[:]) // ShakeHash.Read never returns an error

	/* Compute rhoprime = CRH(key, rnd, mu) */
	state.Reset() // Reuse pooled hasher
	_, _ = state.Write(priv.key[:])
	_, _ = state.Write(rnd[:])
	_, _ = state.Write(mu[:])
	_, _ = state.Read(rhoPrime[:]) // ShakeHash.Read never returns an error

rej:

	/* Sample intermediate vector y */
	polyVecLUniformGamma1(&y, rhoPrime, nonce)
	nonce++

	/* Matrix-vector multiplication */
	z = y
	polyVecLNTT(&z)
	polyVecMatrixPointWiseMontgomery(&w1, mat, &z)
	polyVecKReduce(&w1)
	polyVecKInvNTTToMont(&w1)

	/* Decompose w and call the random oracle */
	polyVecKCAddQ(&w1)
	polyVecKDecompose(&w1, &w0, &w1)
	if err := polyVecKPackW1(sig[:K*POLY_W1_PACKED_BYTES], &w1); err != nil {
		//coverage:ignore
		//rationale: sig buffer is always correctly sized for K*POLY_W1_PACKED_BYTES
		return err
	}

	state.Reset() // Reuse pooled hasher
	if _, err := state.Write(mu[:]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return err
	}
	if _, err := state.Write(sig[:K*POLY_W1_PACKED_BYTES]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return err
	}
	if _, err := state.Read(sig[:C_TILDE_BYTES]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		return err
	}
	if err := polyChallenge(&cp, sig[:C_TILDE_BYTES]); err != nil {
		//coverage:ignore
		//rationale: polyChallenge's sha3 operations never return errors
		return err
	}
	polyNTT(&cp)

	/* Compute z, reject if it reveals secret */
	polyVecLPointWisePolyMontgomery(&z, &cp, &priv.s1)
	polyVecLInvNTTToMont(&z)
	polyVecLAdd(&z, &z, &y)
	polyVecLReduce(&z)
	if polyVecLChkNorm(&z, GAMMA1-BETA) != 0 {
		goto rej
	}

	/* Check that subtracting cs2 does not change high bits of w and low bits
	 * do not reveal secret information */
	polyVecKPointWisePolyMontgomery(&h, &cp, &priv.s2)
	polyVecKInvNTTToMont(&h)
	polyVecKSub(&w0, &w0, &h)
	polyVecKReduce(&w0)
	if polyVecKChkNorm(&w0, GAMMA2-BETA) != 0 {
		goto rej
	}

	/* Compute hints for w1 */
	polyVecKPointWisePolyMontgomery(&h, &cp, &priv.t0)
	polyVecKInvNTTToMont(&h)
	polyVecKReduce(&h)
	if polyVecKChkNorm(&h, GAMMA2) != 0 {
		//coverage:ignore
		//rationale: rejection condition rarely triggers; signature typically succeeds on first attempt
		goto rej
	}

	polyVecKAdd(&w0, &w0, &h)
	n := polyVecKMakeHint(&h, &w0, &w1)
	if n > OMEGA {
		//coverage:ignore
		//rationale: rejection condition rarely triggers; signature typically succeeds on first attempt
		goto rej
	}
	var c [C_TILDE_BYTES]uint8
	copy(c[:], sig[:C_TILDE_BYTES])
	if err := packSig(sig[:CRYPTO_BYTES], c, &z, &h); err != nil {
		//coverage:ignore
		//rationale: packSig only fails for invalid buffer size, but sig is always correctly sized
		return err
	}
	return nil
}

// cryptoSignSignature is the standard hedged-signing entry point. It reads
// RND_BYTES from random and calls [cryptoSignSignatureWithRnd]. If random is
// nil, crypto/rand.Reader is used. Per FIPS 204 §3.4, hedged (randomised)
// signing reduces side-channel and fault-injection leverage relative to the
// deterministic variant; all public ML-DSA-87 signing in this library uses
// this path. (TOB-QRLLIB-6.)
//
// Callers needing an explicit rnd value (the crypto.Signer.Sign
// caller-supplied io.Reader path; ACVP / KAT determinism tests with
// rnd=zero) call [cryptoSignSignatureWithRnd] directly.
func cryptoSignSignature(random io.Reader, sig, m []uint8, ctx []uint8, priv *PrivateKey, mat *[K]polyVecL) error {
	if len(ctx) > 255 {
		return errors.New("mldsa87: invalid context")
	}
	if random == nil {
		random = rand.Reader
	}

	var rnd [RND_BYTES]uint8
	if _, err := io.ReadFull(random, rnd[:]); err != nil {
		return err
	}
	return cryptoSignSignatureWithKeyAndRnd(sig, m, ctx, priv, mat, rnd)
}

// cryptoSignSignatureWithRnd signs m using the explicit rnd value
// (FIPS 204 §3.5; rnd is mixed into the deterministic signing nonce).
// Pass an all-zero rnd for FIPS-204-deterministic signing (used by
// ACVP / KAT vectors); pass entropy from crypto/rand or an
// authenticated source for hedged signing. The crypto.Signer wrapper
// uses this path when the caller supplies an io.Reader.
func cryptoSignSignatureWithRnd(sig, m []uint8, ctx []uint8, sk *[CRYPTO_SECRET_KEY_BYTES]uint8, rnd [RND_BYTES]uint8) error {
	priv, mat, err := privateKeyFromSecretKey(sk)
	if err != nil {
		return err
	}
	defer priv.Zeroize()
	return cryptoSignSignatureWithKeyAndRnd(sig, m, ctx, priv, &mat, rnd)
}

func cryptoSignSignatureWithKeyAndRnd(sig, m []uint8, ctx []uint8, priv *PrivateKey, mat *[K]polyVecL, rnd [RND_BYTES]uint8) error {
	if len(ctx) > 255 {
		return errors.New("mldsa87: invalid context")
	}
	pre := make([]uint8, len(ctx)+2)
	pre[0] = 0
	pre[1] = uint8(len(ctx))
	copy(pre[2:], ctx)
	return cryptoSignSignatureInternal(sig, m, pre[:], rnd, priv, mat)
}

func newPublicKeyFromRaw(pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8) (*PublicKey, error) {
	if pk == nil {
		return nil, errors.New("mldsa87: public key is nil")
	}
	pub := &PublicKey{raw: *pk}
	var rho [SEED_BYTES]uint8
	unpackPk(&rho, &pub.t1, &pub.raw)
	copy(pub.tr[:], sha3.SumSHAKE256(pub.raw[:], TR_BYTES))
	if err := polyVecMatrixExpand(&pub.mat, &rho); err != nil {
		//coverage:ignore
		//rationale: polyVecMatrixExpand's sha3 operations never return errors
		return nil, err
	}
	polyVecKShiftL(&pub.t1)
	polyVecKNTT(&pub.t1)
	return pub, nil
}

func cryptoSignVerifyInternal(sig [CRYPTO_BYTES]uint8, m []uint8, pre []uint8, pub *PublicKey) (bool, error) {
	var buf [K * POLY_W1_PACKED_BYTES]uint8
	var mu [CRH_BYTES]uint8
	var c, c2 [C_TILDE_BYTES]uint8
	var cp poly
	var z polyVecL
	var w1, h polyVecK

	if unpackSig(&c, &z, &h, sig) != 0 {
		return false, nil
	}
	if polyVecLChkNorm(&z, GAMMA1-BETA) != 0 {
		return false, nil
	}

	/* Compute CRH(H(rho, t1), pre, msg) */
	state := getShake256()
	defer putShake256(state)
	if _, err := state.Write(pub.tr[:]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return false, err
	}
	if _, err := state.Write(pre); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return false, err
	}
	if _, err := state.Write(m); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return false, err
	}
	if _, err := state.Read(mu[:CRH_BYTES]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		return false, err
	}

	/* Matrix-vector multiplication; compute Az - c2^dt1 */
	if err := polyChallenge(&cp, c[:]); err != nil {
		//coverage:ignore
		//rationale: polyChallenge's sha3 operations never return errors
		return false, err
	}

	polyVecLNTT(&z)
	polyVecMatrixPointWiseMontgomery(&w1, &pub.mat, &z)

	polyNTT(&cp)
	t1 := pub.t1
	polyVecKPointWisePolyMontgomery(&t1, &cp, &t1)

	polyVecKSub(&w1, &w1, &t1)
	polyVecKReduce(&w1)
	polyVecKInvNTTToMont(&w1)

	/* Reconstruct w1 */
	polyVecKCAddQ(&w1)
	polyVecKUseHint(&w1, &w1, &h)
	if err := polyVecKPackW1(buf[:], &w1); err != nil {
		//coverage:ignore
		//rationale: buf is always correctly sized for K*POLY_W1_PACKED_BYTES
		return false, err
	}

	/* Call random oracle and verify challenge */
	state.Reset() // Reuse pooled hasher
	if _, err := state.Write(mu[:CRH_BYTES]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return false, err
	}
	if _, err := state.Write(buf[:K*POLY_W1_PACKED_BYTES]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return false, err
	}
	if _, err := state.Read(c2[:C_TILDE_BYTES]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		return false, err
	}

	// Use constant-time comparison to prevent timing side-channel attacks
	return subtle.ConstantTimeCompare(c[:], c2[:]) == 1, nil
}

func cryptoSignVerify(sig [CRYPTO_BYTES]uint8, m []uint8, ctx []uint8, pub *PublicKey) (bool, error) {
	// Defense-in-depth nil-check (TOB-QRLLIB-11). The public Verify wrapper
	// also checks, but this internal entry point may be reached by future
	// callers.
	if pub == nil {
		return false, errors.New("mldsa87: public key is nil")
	}
	if len(ctx) > 255 {
		return false, errors.New("mldsa87: invalid context")
	}

	pre := make([]uint8, len(ctx)+2)
	pre[0] = 0
	pre[1] = uint8(len(ctx))
	copy(pre[2:], ctx)

	return cryptoSignVerifyInternal(sig, m, pre[:], pub)
}
