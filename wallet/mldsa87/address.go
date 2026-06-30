package mldsa87

import (
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

func GetMLDSA87Address(pk PK, descriptor Descriptor) ([common.AddressSize]uint8, error) {
	var address [common.AddressSize]uint8
	if !descriptor.IsValid() {
		return address, fmt.Errorf(common.ErrInvalidDescriptor, wallettype.ML_DSA_87)
	}
	return common.UnsafeGetAddress(pk[:], descriptor.ToDescriptor()), nil
}
