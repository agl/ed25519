package edwards25519

// This file contains functions for performing scalar multiplication of points
// and point addition - functionality that is necessary for implementing other
// crypto systems on top of 25519, such as Cramer-Shoup.

// ScalarMult sets r = k*P
// where k is a scalar and P is a point
// This function is constant time

// DoubleScalarMult sets r = k*P + l*Q
// where k and l are scalars and P and Q are points
// This function is constant time

// PointAdd sets r = p + q
// Where p and q are points
// This function is constant time
func PointAdd(r *CompletedGroupElement, p *ExtendedGroupElement, q *CachedGroupElement) {
	geAdd(r, p, q)
}
