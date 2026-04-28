package falcon

const (
	polyDegree    = 1024
	logPolyDegree = 10
)

type (
	coeffPoly []int32
	fprPoly   []fpr
	mqPoly    []uint32
)

func newCoeffPoly() coeffPoly { return make(coeffPoly, polyDegree) }
func newMQPoly() mqPoly       { return make(mqPoly, polyDegree) }
func newFPRPoly() fprPoly     { return make(fprPoly, polyDegree) }
