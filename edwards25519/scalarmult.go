package edwards25519

// This file contains functions for performing scalar multiplication of points
// and point addition - functionality that is necessary for implementing other
// crypto systems on top of 25519, such as Cramer-Shoup.

// ExtendedGroupElementCMove is a constant time conditional move
// Replace (t,u) with (u,u) if b == 1;
// Replace (t,u) with (t,u) if b == 0.
//
// This function is constant time
//
// Preconditions: b in {0,1}.
func ExtendedGroupElementCMove(t, u *ExtendedGroupElement, b int32) {
	FeCMove(&t.X, &u.X, b)
	FeCMove(&t.Y, &u.Y, b)
	FeCMove(&t.Z, &u.Z, b)
	FeCMove(&t.T, &u.T, b)
}

// ScalarMult sets r = k*P
// where k is a scalar and P is a point
// k should be little endian, that is:
//   k = k[0]+256*k[1]+...+256^31 k[31]
// This function is constant time
func ScalarMult(out *ExtendedGroupElement, k *[32]byte, p *ExtendedGroupElement) {
	tmpP := *p
	var tmpPC CachedGroupElement
	var tmpPComp CompletedGroupElement
	var tmpOut CompletedGroupElement
	var tmpOutE ExtendedGroupElement
	out.Zero()

	for _, byte := range k {
		for bitNum := uint(8); bitNum > 0; bitNum-- {
			tmpP.ToCached(&tmpPC)
			geAdd(&tmpOut, out, &tmpPC)

			tmpOut.ToExtended(&tmpOutE)
			ExtendedGroupElementCMove(out, &tmpOutE, int32((byte>>(8-bitNum))&1))

			tmpP.Double(&tmpPComp)
			tmpPComp.ToExtended(&tmpP)
		}
	}
}

// DoubleScalarMult sets r = k*P + l*Q
// where k and l are scalars and P and Q are points
// This function is constant time
func DoubleScalarMult(r *ExtendedGroupElement, k *[32]byte, p *ExtendedGroupElement, l *[32]byte, q *ExtendedGroupElement) {
	var res1, res2 ExtendedGroupElement
	var res2C CachedGroupElement
	var res3 CompletedGroupElement

	ScalarMult(&res1, k, p)
	ScalarMult(&res2, l, q)

	res2.ToCached(&res2C)
	geAdd(&res3, &res1, &res2C)
	res3.ToExtended(r)
}

// PointAdd sets r = p + q
// Where p and q are points
// This function is constant time
func PointAdd(r *CompletedGroupElement, p *ExtendedGroupElement, q *CachedGroupElement) {
	geAdd(r, p, q)
}
