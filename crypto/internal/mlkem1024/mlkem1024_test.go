package mlkem1024

// TODO
/*
// These KATs use fixed d || z and encapsulation randomness. Expected values are
// derived from FIPS 203 and cross-checked against Go's crypto/mlkem package.
// Sources: https://doi.org/10.6028/NIST.FIPS.203,
// https://go.dev/src/crypto/mlkem/, and
// https://go.dev/src/crypto/mlkem/mlkemtest/.

func TestNewDecapsulationKeyKAT(t *testing.T) {
	seed := katSeed()
	dk, err := NewDecapsulationKey(seed[:])
	if err != nil {
		t.Fatalf("NewDecapsulationKey returned error: %v", err)
	}

	if got := dk.Bytes(); !bytes.Equal(got, seed[:]) {
		t.Fatalf("decapsulation key bytes = %x, want %x", got, seed)
	}
	if got := hex.EncodeToString(dk.rho[:]); got != "44b6c66984a868aa92fa02227a086950eb0c8701ed58dc628776b983882e1175" {
		t.Fatalf("rho = %s, want %s", got, "44b6c66984a868aa92fa02227a086950eb0c8701ed58dc628776b983882e1175")
	}
	if got := hex.EncodeToString(dk.h[:]); got != "61349e5c131a7e116a0463861d7d18663c5627c38c7147ddaadfd48acd7a4535" {
		t.Fatalf("H(ekPKE) = %s, want %s", got, "61349e5c131a7e116a0463861d7d18663c5627c38c7147ddaadfd48acd7a4535")
	}

	ek := dk.EncapsulationKey().Bytes()
	if len(ek) != encapsulationKeySize {
		t.Fatalf("encapsulation key length = %d, want %d", len(ek), encapsulationKeySize)
	}
	checkBytesHash(t, "EncapsulationKey().Bytes", ek, "c7b8fa0aa471d5ae18922d6ccad5b31e1d84f92ae723abfd13747018740a8530")
}

func TestEncapsulateInternalKAT(t *testing.T) {
	seed := katSeed()
	dk, err := NewDecapsulationKey(seed[:])
	if err != nil {
		t.Fatalf("NewDecapsulationKey returned error: %v", err)
	}

	m := katMessage()
	var ct [ciphertextSize]byte
	sharedKey := encapsulateTo(&ct, dk.EncapsulationKey(), &m)
	ciphertext := ct[:]

	if got := hex.EncodeToString(sharedKey); got != "a9f52838faed39482c5769f3b8ea6152a09ca981da3a8816ced34be298e54e95" {
		t.Fatalf("shared key = %s, want %s", got, "a9f52838faed39482c5769f3b8ea6152a09ca981da3a8816ced34be298e54e95")
	}
	if len(ciphertext) != ciphertextSize {
		t.Fatalf("ciphertext length = %d, want %d", len(ciphertext), ciphertextSize)
	}
	checkBytesHash(t, "ciphertext", ciphertext, "80d9a3e8af2343685270dace8098e100c634dab5d503939b3e26053f86ee3202")

	decapsulated, err := dk.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate returned error: %v", err)
	}
	if !bytes.Equal(decapsulated, sharedKey) {
		t.Fatalf("decapsulated shared key = %x, want %x", decapsulated, sharedKey)
	}
}

func TestNewEncapsulationKeyExpandsMatrix(t *testing.T) {
	seed := katSeed()
	dk, err := NewDecapsulationKey(seed[:])
	if err != nil {
		t.Fatalf("NewDecapsulationKey returned error: %v", err)
	}

	ek, err := NewEncapsulationKey(dk.EncapsulationKey().Bytes())
	if err != nil {
		t.Fatalf("NewEncapsulationKey returned error: %v", err)
	}

	want := sampleNTT(ek.rho[:], 0, 0)
	if ek.a[0] != want {
		t.Fatal("NewEncapsulationKey did not regenerate A from rho")
	}
}

// These tests consume the official NIST ACVP sample JSON files for ML-KEM.
// Source: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
//
// The checked-in fixtures live under testdata/acvp as gzip-compressed JSON.
// Set MLKEM_ACVP_JSON_DIR to either the gen-val/json-files directory or to one
// specific ML-KEM-* suite directory to run against a fresh ACVP checkout.

func TestACVPJSONKeyGen(t *testing.T) {
	prompt := readACVPFile(t, "ML-KEM-keyGen-FIPS203", "prompt.json")
	expected := readACVPFile(t, "ML-KEM-keyGen-FIPS203", "expectedResults.json")

	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-KEM-1024" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			want := wantGroup.test(t, test.TcID)

			seed := append(decodeACVPHex(t, test.D), decodeACVPHex(t, test.Z)...)
			dk, err := NewDecapsulationKey(seed)
			if err != nil {
				t.Fatalf("tcId %d: NewDecapsulationKey: %v", test.TcID, err)
			}

			if got := dk.EncapsulationKey().Bytes(); !bytes.Equal(got, decodeACVPHex(t, want.EK)) {
				t.Fatalf("tcId %d: encapsulation key mismatch", test.TcID)
			}
			if got := expandedDecapsulationKeyBytes(dk); !bytes.Equal(got, decodeACVPHex(t, want.DK)) {
				t.Fatalf("tcId %d: expanded decapsulation key mismatch", test.TcID)
			}
		}
	}
}

func TestACVPJSONEncapsulation(t *testing.T) {
	prompt := readACVPFile(t, "ML-KEM-encapDecap-FIPS203", "prompt.json")
	expected := readACVPFile(t, "ML-KEM-encapDecap-FIPS203", "expectedResults.json")

	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-KEM-1024" || group.Function != "encapsulation" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			want := wantGroup.test(t, test.TcID)

			ek, err := NewEncapsulationKey(decodeACVPHex(t, test.EK))
			if err != nil {
				t.Fatalf("tcId %d: NewEncapsulationKey: %v", test.TcID, err)
			}
			var m [32]byte
			copy(m[:], decodeACVPHex(t, test.M))
			var ct [ciphertextSize]byte
			gotK := encapsulateTo(&ct, ek, &m)

			if !bytes.Equal(gotK, decodeACVPHex(t, want.K)) {
				t.Fatalf("tcId %d: shared key mismatch", test.TcID)
			}
			if !bytes.Equal(ct[:], decodeACVPHex(t, want.C)) {
				t.Fatalf("tcId %d: ciphertext mismatch", test.TcID)
			}
		}
	}
}

func TestACVPJSONDecapsulation(t *testing.T) {
	prompt := readACVPFile(t, "ML-KEM-encapDecap-FIPS203", "prompt.json")
	expected := readACVPFile(t, "ML-KEM-encapDecap-FIPS203", "expectedResults.json")

	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-KEM-1024" || group.Function != "decapsulation" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			want := wantGroup.test(t, test.TcID)
			dk := newDecapsulationKeyFromExpandedACVP(t, decodeACVPHex(t, test.DK))

			gotK, err := dk.Decapsulate(decodeACVPHex(t, test.C))
			if err != nil {
				t.Fatalf("tcId %d: Decapsulate: %v", test.TcID, err)
			}
			if !bytes.Equal(gotK, decodeACVPHex(t, want.K)) {
				t.Fatalf("tcId %d: shared key mismatch", test.TcID)
			}
		}
	}
}

func TestACVPJSONDecapsulationKeyCheck(t *testing.T) {
	prompt := readACVPFile(t, "ML-KEM-encapDecap-FIPS203", "prompt.json")
	expected := readACVPFile(t, "ML-KEM-encapDecap-FIPS203", "expectedResults.json")

	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-KEM-1024" || group.Function != "decapsulationKeyCheck" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			want := wantGroup.test(t, test.TcID)

			_, err := newDecapsulationKeyFromExpandedACVPCheck(decodeACVPHex(t, test.DK))
			if got := err == nil; got != want.TestPassed {
				t.Fatalf("tcId %d: validation result = %t, want %t", test.TcID, got, want.TestPassed)
			}
		}
	}
}

func TestACVPJSONEncapsulationKeyCheck(t *testing.T) {
	prompt := readACVPFile(t, "ML-KEM-encapDecap-FIPS203", "prompt.json")
	expected := readACVPFile(t, "ML-KEM-encapDecap-FIPS203", "expectedResults.json")

	for _, group := range prompt.TestGroups {
		if group.ParameterSet != "ML-KEM-1024" || group.Function != "encapsulationKeyCheck" {
			continue
		}
		wantGroup := expected.group(t, group.TgID)
		for _, test := range group.Tests {
			want := wantGroup.test(t, test.TcID)

			_, err := NewEncapsulationKey(decodeACVPHex(t, test.EK))
			if got := err == nil; got != want.TestPassed {
				t.Fatalf("tcId %d: validation result = %t, want %t", test.TcID, got, want.TestPassed)
			}
		}
	}
}

type acvpFile struct {
	TestGroups []acvpGroup `json:"testGroups"`
}

type acvpGroup struct {
	TgID         int        `json:"tgId"`
	ParameterSet string     `json:"parameterSet"`
	Function     string     `json:"function"`
	Tests        []acvpTest `json:"tests"`
}

type acvpTest struct {
	TcID       int    `json:"tcId"`
	D          string `json:"d"`
	Z          string `json:"z"`
	EK         string `json:"ek"`
	DK         string `json:"dk"`
	M          string `json:"m"`
	C          string `json:"c"`
	K          string `json:"k"`
	TestPassed bool   `json:"testPassed"`
}

func readACVPFile(t *testing.T, suite, name string) acvpFile {
	t.Helper()

	base := os.Getenv("MLKEM_ACVP_JSON_DIR")
	if base == "" {
		base = filepath.Join("testdata", "acvp")
	}
	path := filepath.Join(base, suite, name)
	if !fileExists(path) && !fileExists(path+".gz") {
		path = filepath.Join(base, name)
	}

	b, path := readACVPBytes(t, path)

	var f acvpFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse ACVP JSON %q: %v", path, err)
	}
	return f
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readACVPBytes(t *testing.T, path string) ([]byte, string) {
	t.Helper()

	b, err := os.ReadFile(path)
	if err == nil {
		return b, path
	}

	gzPath := path + ".gz"
	f, err := os.Open(gzPath)
	if err != nil {
		t.Fatalf("read ACVP JSON %q: %v", path, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("open compressed ACVP JSON %q: %v", gzPath, err)
	}
	defer gz.Close()

	b, err = io.ReadAll(gz)
	if err != nil {
		t.Fatalf("read compressed ACVP JSON %q: %v", gzPath, err)
	}
	return b, gzPath
}

func (f acvpFile) group(t *testing.T, tgID int) acvpGroup {
	t.Helper()
	for _, group := range f.TestGroups {
		if group.TgID == tgID {
			return group
		}
	}
	t.Fatalf("missing ACVP test group %d", tgID)
	return acvpGroup{}
}

func (g acvpGroup) test(t *testing.T, tcID int) acvpTest {
	t.Helper()
	for _, test := range g.Tests {
		if test.TcID == tcID {
			return test
		}
	}
	t.Fatalf("missing ACVP test case %d", tcID)
	return acvpTest{}
}

func decodeACVPHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode ACVP hex: %v", err)
	}
	return b
}

func expandedDecapsulationKeyBytes(dk *DecapsulationKey) []byte {
	b := make([]byte, 0, k*encodingSize12+encapsulationKeySize+64)
	var encoded [encodingSize12]byte
	for i := range dk.s {
		polyByteEncode(encoded[:], dk.s[i])
		b = append(b, encoded[:]...)
	}
	b = append(b, dk.EncapsulationKey().Bytes()...)
	b = append(b, dk.h[:]...)
	b = append(b, dk.z[:]...)
	return b
}

func newDecapsulationKeyFromExpandedACVP(t *testing.T, b []byte) *DecapsulationKey {
	t.Helper()

	dk, err := newDecapsulationKeyFromExpandedACVPCheck(b)
	if err != nil {
		t.Fatal(err)
	}
	return dk
}

func newDecapsulationKeyFromExpandedACVPCheck(b []byte) (*DecapsulationKey, error) {
	const expandedSize = k*encodingSize12 + encapsulationKeySize + 64
	if len(b) != expandedSize {
		return nil, errors.New("invalid expanded decapsulation key length")
	}

	dk := &DecapsulationKey{}
	for i := range dk.s {
		var err error
		dk.s[i], err = polyByteDecode(b[:encodingSize12])
		if err != nil {
			return nil, err
		}
		b = b[encodingSize12:]
	}

	ek, err := NewEncapsulationKey(b[:encapsulationKeySize])
	if err != nil {
		return nil, err
	}
	dk.h = ek.h
	dk.encryptionKey = ek.encryptionKey
	b = b[encapsulationKeySize:]

	if !bytes.Equal(dk.h[:], b[:32]) {
		return nil, errors.New("expanded decapsulation key has inconsistent H(ek)")
	}
	b = b[32:]
	copy(dk.z[:], b[:32])

	return dk, nil
}

func katSeed() [seedSize]byte {
	var seed [seedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

func katMessage() [32]byte {
	var m [32]byte
	for i := range m {
		m[i] = byte(255 - 7*i)
	}
	return m
}
*/
