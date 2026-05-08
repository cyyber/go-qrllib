package falcon1024

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func TestPublicKeyCodec(t *testing.T) {
	pub := mustDecodeHex(t, verifyRawKATPublicKeyHex)

	t.Run("reference KAT", func(t *testing.T) {
		// Derived from the Falcon reference implementation test_falcon.c
		// ntru_pkey_1024 array.
		// Source: https://falcon-sign.info/impl/test_falcon.c.html
		if len(pub) != publicKeySize {
			t.Fatalf("reference public key length = %d, want %d", len(pub), publicKeySize)
		}
		if pub[0] != publicKeyHeader {
			t.Fatalf("reference public key header = %#x, want %#x", pub[0], publicKeyHeader)
		}

		h, err := pkDecode(pub)
		if err != nil {
			t.Fatal(err)
		}

		got := make([]byte, publicKeySize)
		if err := pkEncode(got, h); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, pub) {
			t.Fatal("pkEncode(pkDecode(reference public key)) did not round-trip")
		}
	})

	t.Run("rejects invalid input", func(t *testing.T) {
		testCases := []struct {
			name string
			in   []byte
		}{
			{
				name: "short",
				in:   pub[:publicKeySize-1],
			},
			{
				name: "long",
				in:   append(bytes.Clone(pub), 0),
			},
			{
				name: "invalid header",
				in: func() []byte {
					in := bytes.Clone(pub)
					in[0] ^= 0xff
					return in
				}(),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := pkDecode(tc.in); err == nil {
					t.Fatal("pkDecode accepted invalid public key")
				}
			})
		}
	})
}

func TestPrivateKeyCodec(t *testing.T) {
	f := mustDecodeSmallPolynomialHex(t, ntru_f_1024Hex)
	g := mustDecodeSmallPolynomialHex(t, ntru_g_1024Hex)
	ntruF := mustDecodeSmallPolynomialHex(t, ntru_F_1024Hex)

	sk := make([]byte, privateKeySize)
	if err := skEncode(sk, f, g, ntruF); err != nil {
		t.Fatal(err)
	}

	t.Run("reference polynomials", func(t *testing.T) {
		// test_falcon.c publishes component private-key polynomials, not a
		// serialized secret key. Use those reference polynomials to check that our
		// private-key codec round-trips the reference components.
		// Source: https://falcon-sign.info/impl/test_falcon.c.html
		gotF, gotG, gotNTRUF, err := skDecode(sk)
		if err != nil {
			t.Fatal(err)
		}
		if gotF != f || gotG != g || gotNTRUF != ntruF {
			t.Fatal("skDecode(skEncode(reference polynomials)) did not round-trip")
		}
	})

	t.Run("rejects invalid input", func(t *testing.T) {
		testCases := []struct {
			name string
			in   []byte
		}{
			{
				name: "short",
				in:   sk[:privateKeySize-1],
			},
			{
				name: "long",
				in:   append(bytes.Clone(sk), 0),
			},
			{
				name: "invalid header",
				in: func() []byte {
					in := bytes.Clone(sk)
					in[0] ^= 0xff
					return in
				}(),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				if _, _, _, err := skDecode(tc.in); err == nil {
					t.Fatal("skDecode accepted invalid private key")
				}
			})
		}
	})
}

func TestSignatureCodec(t *testing.T) {
	tc := verifyRawKATs[0]
	nonceBytes := mustDecodeHex(t, tc.nonceHex)
	var nonce [nonceSize]byte
	copy(nonce[:], nonceBytes)
	s2 := decodeVerifyRawKATSignature(t, mustDecodeHex(t, tc.signatureHex))

	sig := make([]byte, signatureSize)
	if err := sigEncode(sig, nonce, s2); err != nil {
		t.Fatal(err)
	}

	t.Run("reference raw s2 KATs", func(t *testing.T) {
		// The s2 vectors are decoded from the Falcon reference implementation
		// KAT_SIG_1024 raw verify vectors. Those raw vectors use a 32-byte hash
		// seed, not the 40-byte nonce carried by padded Falcon signatures, so the
		// seed is zero-extended only to exercise this package's padded codec.
		// Source: https://falcon-sign.info/impl/test_falcon.c.html
		for _, tc := range verifyRawKATs {
			t.Run(tc.message, func(t *testing.T) {
				nonceBytes := mustDecodeHex(t, tc.nonceHex)
				var nonce [nonceSize]byte
				copy(nonce[:], nonceBytes)

				wantS2 := decodeVerifyRawKATSignature(t, mustDecodeHex(t, tc.signatureHex))

				sig := make([]byte, signatureSize)
				if err := sigEncode(sig, nonce, wantS2); err != nil {
					t.Fatal(err)
				}

				gotNonce, gotS2, err := sigDecode(sig)
				if err != nil {
					t.Fatal(err)
				}
				if gotNonce != nonce {
					t.Fatal("sigDecode returned unexpected nonce")
				}
				if gotS2 != wantS2 {
					t.Fatal("sigDecode returned unexpected s2")
				}
			})
		}
	})

	t.Run("rejects invalid input", func(t *testing.T) {
		testCases := []struct {
			name string
			in   []byte
		}{
			{
				name: "short",
				in:   sig[:signatureSize-1],
			},
			{
				name: "long",
				in:   append(bytes.Clone(sig), 0),
			},
			{
				name: "invalid header",
				in: func() []byte {
					in := bytes.Clone(sig)
					in[0] ^= 0xff
					return in
				}(),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				if _, _, err := sigDecode(tc.in); err == nil {
					t.Fatal("sigDecode accepted invalid signature")
				}
			})
		}
	})

	t.Run("rejects invalid output buffer", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			out  []byte
		}{
			{
				name: "short",
				out:  make([]byte, signatureSize-1),
			},
			{
				name: "long",
				out:  make([]byte, signatureSize+1),
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := sigEncode(tc.out, nonce, s2); err == nil {
					t.Fatal("sigEncode accepted invalid signature buffer")
				}
			})
		}
	})

	t.Run("rejects non-zero padding", func(t *testing.T) {
		sig := make([]byte, signatureSize)
		sig[0] = signatureHeader
		copy(sig[headerSize:signaturePrefixSize], nonce[:])
		written, err := compressedEncode(sig[signaturePrefixSize:], s2)
		if err != nil {
			t.Fatal(err)
		}
		if written >= signatureSize-signaturePrefixSize {
			t.Fatal("reference signature unexpectedly leaves no padding byte to corrupt")
		}

		sig[signaturePrefixSize+written] = 1
		if _, _, err := sigDecode(sig); err == nil {
			t.Fatal("sigDecode accepted non-zero padded signature bytes")
		}
	})
}

func TestCompressedEncode(t *testing.T) {
	// The expected lengths and digests were derived from the Falcon reference
	// implementation comp_encode applied to KAT_SIG_1024 s2 values.
	// Source: https://falcon-sign.info/impl/test_falcon.c.html
	expected := []struct {
		length int
		digest string
	}{
		{1231, "d44837d1e8addd9a6ff73afd7ff585dc82d17e07e9167dc6a567633acdc4fd92"},
		{1234, "9003f73ea73862807846698a9bf2e7bde2b14e312569324dc42c79f2ba49dab2"},
		{1232, "4937e0c409a0f0811f85047301d07b5db8eb5601265a49fb45aa570a25e9faeb"},
		{1227, "a90b61d2541872c90e3f44b6941c1d719509b0d3a661115cdb244ffaa108f839"},
		{1232, "5ba3c96353176f6e533a8ea6167d31ee50d4eb8b581203407ef8ff32568d0e92"},
		{1230, "2e7da586f788b28435f575119182c775a4b3e4f88acddd1d30c14483d3134a44"},
		{1229, "8be0da517c3ecc50e70156b4bdd620d896c168ad13fd6e94d3a8740fc961d97b"},
		{1229, "e382fc50731f464598e1e8768847a0bd60ce1944bc805cf8452aa870e538edf0"},
		{1232, "7bc474ae78e6f20776ea1682582c841186495fc58ce346ec4102231c00792100"},
		{1229, "1798601e97a4909b0f5291e17734de7ba4f23f6d1666e601912e4ab406cfdf9f"},
	}

	for i, tc := range verifyRawKATs {
		t.Run(tc.message, func(t *testing.T) {
			s2 := decodeVerifyRawKATSignature(t, mustDecodeHex(t, tc.signatureHex))
			dst := make([]byte, signatureSize-signaturePrefixSize)

			written, err := compressedEncode(dst, s2)
			if err != nil {
				t.Fatal(err)
			}
			if written != expected[i].length {
				t.Fatalf("compressed length = %d, want %d", written, expected[i].length)
			}

			digest := sha256.Sum256(dst[:written])
			if got := hex.EncodeToString(digest[:]); got != expected[i].digest {
				t.Fatalf("compressed digest = %s, want %s", got, expected[i].digest)
			}
		})
	}
}

func TestCompressedEncodeRejectsInvalidInput(t *testing.T) {
	outOfRange := smallPolynomial{}
	outOfRange[0] = maxCompressedCoefficient + 1

	testCases := []struct {
		name string
		s2   smallPolynomial
		dst  []byte
		err  error
	}{
		{
			name: "out of range coefficient",
			s2:   outOfRange,
			dst:  make([]byte, signatureSize-signaturePrefixSize),
			err:  errCompressedCoefficientOutOfRange,
		},
		{
			name: "tiny buffer",
			s2:   smallPolynomial{},
			dst:  make([]byte, 1),
			err:  errCompressedSignatureTooLarge,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compressedEncode(tc.dst, tc.s2); !errors.Is(err, tc.err) {
				t.Fatalf("compressedEncode error = %v, want %v", err, tc.err)
			}
		})
	}
}

func TestCompressedDecodeRejectsNonZeroTrailingBits(t *testing.T) {
	var s2 smallPolynomial
	s2[0] = 128

	buf := make([]byte, signatureSize-signaturePrefixSize)
	written, err := compressedEncode(buf, s2)
	if err != nil {
		t.Fatal(err)
	}

	buf[written-1] |= 1
	if _, _, err := compressedDecode(buf[:written]); !errors.Is(err, errInvalidSignatureEncoding) {
		t.Fatalf("compressedDecode error = %v, want %v", err, errInvalidSignatureEncoding)
	}
}

func TestTrimI8Encode(t *testing.T) {
	// The expected lengths and digests were derived from the Falcon reference
	// implementation trim_i8_encode applied to test_falcon.c ntru_*_1024 arrays.
	// Source: https://falcon-sign.info/impl/test_falcon.c.html
	testCases := []struct {
		name   string
		p      smallPolynomial
		bits   int
		length int
		digest string
	}{
		{
			name:   "f",
			p:      mustDecodeSmallPolynomialHex(t, ntru_f_1024Hex),
			bits:   fgBits,
			length: 640,
			digest: "0fd26e919032455f5e3a2c7ed5811cbb7bda70b453a538d18103b3620c082857",
		},
		{
			name:   "g",
			p:      mustDecodeSmallPolynomialHex(t, ntru_g_1024Hex),
			bits:   fgBits,
			length: 640,
			digest: "b44b290bffb4bdb66b216c88d0de69e0fa877e4035d27e6ebf055d6844d01ee2",
		},
		{
			name:   "F",
			p:      mustDecodeSmallPolynomialHex(t, ntru_F_1024Hex),
			bits:   ntruFBits,
			length: 1024,
			digest: "b79fd83fac715a2942d4d76ad5c6b8b1ce62a9f35b4cdad78963db5c46c86939",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dst := make([]byte, n)
			written, err := trimI8Encode(dst, tc.p, tc.bits)
			if err != nil {
				t.Fatal(err)
			}
			if written != tc.length {
				t.Fatalf("trim_i8 length = %d, want %d", written, tc.length)
			}

			digest := sha256.Sum256(dst[:written])
			if got := hex.EncodeToString(digest[:]); got != tc.digest {
				t.Fatalf("trim_i8 digest = %s, want %s", got, tc.digest)
			}
		})
	}
}

func TestTrimI8DecodeRejectsForbiddenValues(t *testing.T) {
	testCases := []struct {
		name string
		bits int
		src  []byte
	}{
		{
			name: "fg",
			bits: fgBits,
			src: func() []byte {
				src := make([]byte, (n*fgBits+7)>>3)
				src[0] = 0x80 // first 5-bit field is 10000, i.e. forbidden -16.
				return src
			}(),
		},
		{
			name: "F",
			bits: ntruFBits,
			src: func() []byte {
				src := make([]byte, (n*ntruFBits+7)>>3)
				src[0] = 0x80 // forbidden -128.
				return src
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := trimI8Decode(tc.src, tc.bits); err == nil {
				t.Fatal("trimI8Decode accepted forbidden value")
			}
		})
	}
}
