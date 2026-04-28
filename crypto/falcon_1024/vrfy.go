package falcon

import "errors"

var (
	ErrComputePublicDivisionByZero          = errors.New("computePublic encountered division by zero")
	ErrCompletePrivateDivisionByZero        = errors.New("completePrivate encountered division by zero")
	ErrCompletePrivateCoefficientOutOfRange = errors.New("completePrivate coefficient exceeds signed 8-bit range")
)

func verifyRaw(c0, s2 coeffPoly, h mqPoly) bool {
	tt := newMQPoly()

	for u := range polyDegree {
		tt[u] = mqConvSmall(s2[u])
	}

	mqNTT(tt)
	mqPolyMontyMulNTT(tt, h)
	mqINTT(tt)

	c0q := newMQPoly()
	for i := range polyDegree {
		c0q[i] = uint32(c0[i])
	}
	mqPolySub(tt, c0q)

	s1 := newCoeffPoly()
	for i := range polyDegree {
		w := int32(tt[i])
		if w > modulusQ/2 {
			w -= modulusQ
		}
		s1[i] = w
	}

	return isShort(s1, s2)
}

func computePublic(f, g coeffPoly) (mqPoly, error) {
	tt := newMQPoly()
	h := newMQPoly()

	for i := range polyDegree {
		tt[i] = mqConvSmall(f[i])
		h[i] = mqConvSmall(g[i])
	}

	mqNTT(h)
	mqNTT(tt)

	for i := range polyDegree {
		if tt[i] == 0 {
			return mqPoly{}, ErrComputePublicDivisionByZero
		}
		h[i] = mqDiv12289(h[i], tt[i])
	}

	mqINTT(h)

	return h, nil
}

func completePrivate(f, g, ntruF coeffPoly) (coeffPoly, error) {
	t1 := newMQPoly()
	t2 := newMQPoly()

	for i := range polyDegree {
		t1[i] = mqConvSmall(g[i])
		t2[i] = mqConvSmall(ntruF[i])
	}

	mqNTT(t1)
	mqNTT(t2)
	mqPolyToMonty(t1)
	mqPolyMontyMulNTT(t1, t2)

	for i := range polyDegree {
		t1[i] = mqConvSmall(f[i])
	}

	mqNTT(t2)

	for i := range polyDegree {
		if t2[i] == 0 {
			return nil, ErrCompletePrivateDivisionByZero
		}
		t1[i] = mqDiv12289(t1[i], t2[i])
	}

	mqINTT(t1)

	ntruG := newCoeffPoly()
	for i := range polyDegree {
		gi := int32(t1[i])
		if gi > modulusQ/2 {
			gi -= modulusQ
		}
		if gi < -127 || gi > 127 {
			return nil, ErrCompletePrivateCoefficientOutOfRange
		}
		ntruG[i] = gi
	}

	return ntruG, nil
}
