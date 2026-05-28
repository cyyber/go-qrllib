package common

import (
	"strings"
	"testing"

	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

func TestIsValidAddress(t *testing.T) {
	// Valid address: "Q" + 128 hex chars (64 bytes * 2)
	validAddr := "Q" + strings.Repeat("ab", AddressSize)

	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{
			name:     "valid address",
			addr:     validAddr,
			expected: true,
		},
		{
			name:     "valid address with uppercase hex",
			addr:     "Q" + strings.Repeat("AB", AddressSize),
			expected: true,
		},
		{
			name:     "invalid address with wrong mixed-case checksum",
			addr:     "Q" + strings.Repeat("aB", AddressSize),
			expected: false,
		},
		{
			name:     "invalid - missing Q prefix",
			addr:     strings.Repeat("ab", AddressSize+1),
			expected: false,
		},
		{
			name:     "invalid - lowercase q prefix",
			addr:     "q" + strings.Repeat("ab", AddressSize),
			expected: false,
		},
		{
			name:     "invalid - too short",
			addr:     "Q" + strings.Repeat("ab", AddressSize-1),
			expected: false,
		},
		{
			name:     "invalid - too long",
			addr:     "Q" + strings.Repeat("ab", AddressSize+1),
			expected: false,
		},
		{
			name:     "invalid - non-hex characters",
			addr:     "Q" + strings.Repeat("zz", AddressSize),
			expected: false,
		},
		{
			name:     "invalid - empty string",
			addr:     "",
			expected: false,
		},
		{
			name:     "invalid - just Q",
			addr:     "Q",
			expected: false,
		},
		{
			name:     "invalid - contains spaces",
			addr:     "Q" + strings.Repeat("ab", AddressSize-1) + " a",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidAddress(tt.addr); got != tt.expected {
				t.Errorf("IsValidAddress(%q) = %v, want %v", tt.addr, got, tt.expected)
			}
		})
	}
}

func TestToChecksumAddress(t *testing.T) {
	lowerAddr := "Q" + strings.Repeat("ab", AddressSize)

	checksummed, err := ToChecksumAddress(lowerAddr)
	if err != nil {
		t.Fatalf("ToChecksumAddress returned error: %v", err)
	}
	if len(checksummed) != len(lowerAddr) {
		t.Fatalf("checksummed address length = %d, want %d", len(checksummed), len(lowerAddr))
	}
	if checksummed[0] != 'Q' {
		t.Fatalf("checksummed address prefix = %q, want Q", checksummed[0])
	}
	if strings.ToLower(checksummed[1:]) != lowerAddr[1:] {
		t.Fatalf("checksummed address changed address bytes: %s", checksummed)
	}
	if checksummed == lowerAddr {
		t.Fatalf("checksummed address should use mixed case for this vector")
	}
}

func TestIsValidChecksumAddress(t *testing.T) {
	lowerAddr := "Q" + strings.Repeat("ab", AddressSize)
	upperAddr := "Q" + strings.Repeat("AB", AddressSize)
	checksummed, err := ToChecksumAddress(lowerAddr)
	if err != nil {
		t.Fatalf("ToChecksumAddress returned error: %v", err)
	}

	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{
			name:     "lowercase compatibility form",
			addr:     lowerAddr,
			expected: true,
		},
		{
			name:     "uppercase compatibility form",
			addr:     upperAddr,
			expected: true,
		},
		{
			name:     "valid checksum",
			addr:     checksummed,
			expected: true,
		},
		{
			name:     "invalid mixed case checksum",
			addr:     "Q" + strings.Repeat("aB", AddressSize),
			expected: false,
		},
		{
			name:     "invalid prefix",
			addr:     "q" + strings.Repeat("ab", AddressSize),
			expected: false,
		},
		{
			name:     "invalid hex",
			addr:     "Q" + strings.Repeat("ab", AddressSize-1) + "zz",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidChecksumAddress(tt.addr); got != tt.expected {
				t.Errorf("IsValidChecksumAddress(%q) = %v, want %v", tt.addr, got, tt.expected)
			}
		})
	}
}

func TestChecksumAddressDetectsTypos(t *testing.T) {
	lowerAddr := "Q" + strings.Repeat("ab", AddressSize)
	checksummed, err := ToChecksumAddress(lowerAddr)
	if err != nil {
		t.Fatalf("ToChecksumAddress returned error: %v", err)
	}

	tampered := []byte(checksummed)
	for i := 1; i < len(tampered); i++ {
		if tampered[i] >= 'a' && tampered[i] <= 'f' {
			tampered[i] = byte(strings.ToUpper(string(tampered[i]))[0])
			if string(tampered) != checksummed {
				break
			}
		} else if tampered[i] >= 'A' && tampered[i] <= 'F' {
			tampered[i] = byte(strings.ToLower(string(tampered[i]))[0])
			break
		}
	}

	if IsValidChecksumAddress(string(tampered)) {
		t.Fatalf("tampered checksum address should be invalid: %s", string(tampered))
	}
}

func TestIsValidAddressLength(t *testing.T) {
	// Verify expected address length: Q + (AddressSize * 2) hex chars
	expectedLen := 1 + AddressSize*2

	validAddr := "Q" + strings.Repeat("00", AddressSize)
	if len(validAddr) != expectedLen {
		t.Errorf("Expected address length %d, got %d", expectedLen, len(validAddr))
	}

	if !IsValidAddress(validAddr) {
		t.Error("Address with correct length should be valid")
	}
}

func TestGetAddressMLDSA87(t *testing.T) {
	descBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
	desc := descriptor.New(descBytes)
	pk := make([]byte, MLDSA87PKSize)

	got, err := GetAddress(pk, desc)
	if err != nil {
		t.Fatalf("GetAddress returned error: %v", err)
	}

	want := UnsafeGetAddress(pk, desc)
	if got != want {
		t.Error("GetAddress output mismatch with UnsafeGetAddress")
	}
}

func TestGetAddressRejectsSphincsPlus256s(t *testing.T) {
	descBytes := descriptor.GetDescriptorBytes(wallettype.SPHINCSPLUS_256S, [2]byte{0x00, 0x00})
	desc := descriptor.New(descBytes)
	pk := make([]byte, SPHINCSPlus256sPKSize)

	if _, err := GetAddress(pk, desc); err == nil {
		t.Fatal("GetAddress accepted reserved SPHINCSPLUS_256S descriptor")
	}
}

func TestGetAddressInvalidDescriptor(t *testing.T) {
	desc := descriptor.New([descriptor.DescriptorSize]byte{0xFF, 0x00, 0x00})
	_, err := GetAddress(make([]byte, 64), desc)
	if err == nil {
		t.Error("Expected error for invalid descriptor")
	}
}

func TestGetAddressInvalidPKSize(t *testing.T) {
	descBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
	desc := descriptor.New(descBytes)
	_, err := GetAddress(make([]byte, 32), desc)
	if err == nil {
		t.Error("Expected error for invalid public key size")
	}
}
