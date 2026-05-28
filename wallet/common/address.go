package common

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
	"golang.org/x/crypto/sha3"
)

/*
UnsafeGetAddress builds the address bytes from a validated descriptor and public key.

Rationale: this is a fast-path used by wallet implementations that already validate
the descriptor type and public key length during construction. Skipping checks avoids
repeat validation on every call, but it is unsafe for untrusted inputs.

Callers MUST ensure:
  - desc.IsValid() is true for the intended wallet type
  - pk is the correct length for that wallet type
*/
func UnsafeGetAddress(pk []byte, desc descriptor.Descriptor) [AddressSize]byte {
	// noinspection GoBoolExpressions
	if AddressSize > 64 {
		//coverage:ignore
		//rationale: compile-time assertion, AddressSize is a constant (64) which is <= 64
		panic("AddressSize must be <= 64")
	}

	sh := sha3.NewShake256()
	_, _ = sh.Write(desc.ToBytes())
	_, _ = sh.Write(pk)

	var addr [AddressSize]byte
	_, _ = sh.Read(addr[:]) // take the first N bytes
	return addr
}

// GetAddress validates the descriptor and public key length, then derives the address.
// It is the safe wrapper around UnsafeGetAddress for untrusted inputs.
func GetAddress(pk []byte, desc descriptor.Descriptor) ([AddressSize]byte, error) {
	var addr [AddressSize]byte
	if !desc.IsValid() {
		return addr, fmt.Errorf(ErrInvalidDescriptor, wallettype.WalletType(desc.Type()))
	}
	expectedSize, err := expectedPKSize(desc)
	if err != nil {
		//coverage:ignore
		//rationale: desc.IsValid() above already validates the wallet type
		return addr, err
	}
	if len(pk) != expectedSize {
		return addr, fmt.Errorf(ErrInvalidPKSize, wallettype.WalletType(desc.Type()), len(pk), expectedSize)
	}
	return UnsafeGetAddress(pk, desc), nil
}

func expectedPKSize(desc descriptor.Descriptor) (int, error) {
	switch wallettype.WalletType(desc.Type()) {
	case wallettype.ML_DSA_87:
		return MLDSA87PKSize, nil
	default:
		//coverage:ignore
		//rationale: only called from GetAddress after desc.IsValid() check
		return 0, fmt.Errorf(ErrInvalidDescriptor, wallettype.WalletType(desc.Type()))
	}
}

// ToChecksumAddress returns the EIP-55-style mixed-case representation of a QRL
// address using SHAKE256 instead of Keccak. Lowercase address strings remain the
// canonical non-checksummed form; this helper is intended for display and typo
// detection.
func ToChecksumAddress(addr string) (string, error) {
	body, err := addressBody(addr)
	if err != nil {
		return "", err
	}

	lowerBody := strings.ToLower(body)
	hash := shake256ASCIIHex(lowerBody)
	hashHex := hex.EncodeToString(hash)

	var checksummed strings.Builder
	checksummed.Grow(1 + len(lowerBody))
	checksummed.WriteByte('Q')

	for i, char := range lowerBody {
		if char >= 'a' && char <= 'f' && hashHex[i] >= '8' {
			checksummed.WriteRune(unicode.ToUpper(char))
			continue
		}
		checksummed.WriteRune(char)
	}

	return checksummed.String(), nil
}

// IsValidChecksumAddress validates a checksummed QRL address. All-lowercase and
// all-uppercase addresses are accepted as non-checksummed compatibility forms,
// matching the common EIP-55 validation policy. Mixed-case addresses must match
// the SHAKE256 checksum exactly.
func IsValidChecksumAddress(addr string) bool {
	body, err := addressBody(addr)
	if err != nil {
		return false
	}
	if body == strings.ToLower(body) || body == strings.ToUpper(body) {
		return true
	}

	checksummed, err := ToChecksumAddress(addr)
	if err != nil {
		return false
	}
	return addr == checksummed
}

// IsValidAddress validates a QRL address string.
// A valid address has the format "Q" followed by AddressSize*2 hex characters.
// Lowercase and uppercase inputs are accepted as non-checksummed compatibility
// forms; mixed-case inputs must pass the SHAKE256 checksum.
func IsValidAddress(addr string) bool {
	return IsValidChecksumAddress(addr)
}

func addressBody(addr string) (string, error) {
	expectedLen := 1 + AddressSize*2
	if len(addr) != expectedLen {
		return "", fmt.Errorf("address must be %d characters", expectedLen)
	}
	if addr[0] != 'Q' {
		return "", fmt.Errorf("address must start with Q")
	}

	body := addr[1:]
	if _, err := hex.DecodeString(body); err != nil {
		return "", fmt.Errorf("address contains invalid hex: %w", err)
	}
	return body, nil
}

func shake256ASCIIHex(body string) []byte {
	sh := sha3.NewShake256()
	_, _ = sh.Write([]byte(body))

	hash := make([]byte, AddressSize)
	_, _ = sh.Read(hash)
	return hash
}
