package falcon1024

func solveNTRU(f, g smallPolynomial) (ntruF, ntruG smallPolynomial, ok bool) {
	// TODO
	return smallPolynomial{}, smallPolynomial{}, false
}

func solveNTRUDeepest(f, g smallPolynomial) (zintF, zintG []uint32, ok bool) {
	// TODO
	return zintF, zintG, ok
}

func solveNTRUIntermediate(
	f, g smallPolynomial,
	depth int,
	prevF, prevG []uint32,
) (nextF, nextG []uint32, ok bool) {
	// TODO
	return nextF, nextG, ok
}

func solveNTRUBinaryDepth1(
	f, g smallPolynomial,
	prevF, prevG []uint32,
) (nextF, nextG []uint32, ok bool) {
	// TODO
	return nextF, nextG, ok
}

func solveNTRUBinaryDepth0(
	f, g smallPolynomial,
	prevF, prevG []uint32,
) (bigF, bigG []uint32, ok bool) {
	// TODO
	return bigF, bigG, ok
}
