package mldsa87

import "errors"

type polyVecK struct {
	vec [K]poly
}

type polyVecL struct {
	vec [L]poly
}

func polyVecLUniformGamma1(v *polyVecL, seed [CRH_BYTES]uint8, nonce uint16) {
	for i := range uint16(L) {
		polyUniformGamma1(&v.vec[i], seed, L*nonce+i)
	}
}

func polyVecLReduce(v *polyVecL) {
	for i := range L {
		polyReduce(&v.vec[i])
	}
}

func polyVecLAdd(w, u, v *polyVecL) {
	for i := range L {
		polyAdd(&w.vec[i], &u.vec[i], &v.vec[i])
	}
}

func polyVecLNTT(v *polyVecL) {
	for i := range L {
		polyNTT(&v.vec[i])
	}
}

func polyVecLInvNTTToMont(v *polyVecL) {
	for i := range L {
		polyInvNTTToMont(&v.vec[i])
	}
}

func polyVecLPointWisePolyMontgomery(r *polyVecL, a *poly, v *polyVecL) {
	for i := range L {
		polyPointWiseMontgomery(&r.vec[i], a, &v.vec[i])
	}
}

func polyVecMatrixExpand(mat *[K]polyVecL, rho *[SEED_BYTES]uint8) error {
	for i := range K {
		for j := range L {
			if err := polyUniform(&mat[i].vec[j], rho, (uint16(i)<<8)+uint16(j)); err != nil {
				//coverage:ignore
				//rationale: polyUniform's sha3 operations never return errors
				return err
			}
		}
	}
	return nil
}

func polyVecLChkNorm(v *polyVecL, bound int32) (ret int) {
	for i := range L {
		if polyChkNorm(&v.vec[i], bound) != 0 {
			return 1
		}
	}

	return 0
}

func polyVecKAdd(w, u, v *polyVecK) {
	for i := range K {
		polyAdd(&w.vec[i], &u.vec[i], &v.vec[i])
	}
}
func polyVecKSub(w, u, v *polyVecK) {
	for i := range K {
		polySub(&w.vec[i], &u.vec[i], &v.vec[i])
	}
}

func polyVecKShiftL(v *polyVecK) {
	for i := range K {
		polyShiftL(&v.vec[i])
	}
}

func polyVecKNTT(v *polyVecK) {
	for i := range K {
		polyNTT(&v.vec[i])
	}
}

func polyVecKInvNTTToMont(v *polyVecK) {
	for i := range K {
		polyInvNTTToMont(&v.vec[i])
	}
}

func polyVecKPointWisePolyMontgomery(r *polyVecK, a *poly, v *polyVecK) {
	for i := range K {
		polyPointWiseMontgomery(&r.vec[i], a, &v.vec[i])
	}
}

func polyVecKChkNorm(v *polyVecK, bound int32) (ret int) {
	for i := range K {
		if polyChkNorm(&v.vec[i], bound) != 0 {
			return 1
		}
	}
	return 0
}

func polyVecKPower2Round(v1, v0, v *polyVecK) {
	for i := range K {
		polyPower2Round(&v1.vec[i], &v0.vec[i], &v.vec[i])
	}
}

func polyVecKDecompose(v1, v0, v *polyVecK) {
	for i := range K {
		polyDecompose(&v1.vec[i], &v0.vec[i], &v.vec[i])
	}
}

func polyVecKMakeHint(h, v0, v1 *polyVecK) (s uint) {
	for i := range K {
		s += polyMakeHint(&h.vec[i], &v0.vec[i], &v1.vec[i])
	}
	return s
}

func polyVecKUseHint(w, u, h *polyVecK) {
	for i := range K {
		polyUseHint(&w.vec[i], &u.vec[i], &h.vec[i])
	}
}

func polyVecLPointWiseAccMontgomery(w *poly, u, v *polyVecL) {
	var t poly

	polyPointWiseMontgomery(w, &u.vec[0], &v.vec[0])
	for i := 1; i < L; i++ {
		polyPointWiseMontgomery(&t, &u.vec[i], &v.vec[i])
		polyAdd(w, w, &t)
	}
}

func polyVecMatrixPointWiseMontgomery(t *polyVecK, mat *[K]polyVecL, v *polyVecL) {
	for i := range K {
		polyVecLPointWiseAccMontgomery(&t.vec[i], &mat[i], v)
	}
}

func polyVecLUniformETA(v *polyVecL, seed *[CRH_BYTES]uint8, nonce uint16) error {
	for i := range L {
		if err := polyUniformEta(&v.vec[i], seed, nonce); err != nil {
			//coverage:ignore
			//rationale: polyUniformEta's sha3 operations never return errors
			return err
		}
		nonce++
	}
	return nil
}

func polyVecKUniformETA(v *polyVecK, seed *[CRH_BYTES]uint8, nonce uint16) error {
	for i := range K {
		if err := polyUniformEta(&v.vec[i], seed, nonce); err != nil {
			//coverage:ignore
			//rationale: polyUniformEta's sha3 operations never return errors
			return err
		}
		nonce++
	}
	return nil
}

func polyVecKReduce(v *polyVecK) {
	for i := range K {
		polyReduce(&v.vec[i])
	}
}

func polyVecKCAddQ(v *polyVecK) {
	for i := range K {
		polyCAddQ(&v.vec[i])
	}
}

func polyVecKPackW1(r []uint8, w1 *polyVecK) error {
	if len(r) != K*POLY_W1_PACKED_BYTES {
		//coverage:ignore
		//rationale: internal callers always pass correctly sized buffers
		return errors.New("mldsa87: invalid length")
	}
	for i := range K {
		polyW1Pack(r[i*POLY_W1_PACKED_BYTES:], &w1.vec[i])
	}
	return nil
}
