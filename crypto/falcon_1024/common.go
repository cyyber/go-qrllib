package falcon

import "golang.org/x/crypto/sha3"

func hashToPointVartime(sc sha3.ShakeHash) (coeffPoly, error) {
	return coeffPoly{}, nil
}

func isShort(s1, s2 coeffPoly) bool {
	return false
}

func isShortHalf(sqn uint32, s2 coeffPoly) bool {
	return false
}
