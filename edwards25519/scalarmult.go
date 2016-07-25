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
// It executes exactly 256 point additions, 256 point doublings and 256 conditional moves
func ScalarMult(out *ExtendedGroupElement, k *[32]byte, p *ExtendedGroupElement) {
	tmpP := *p

	var cach CachedGroupElement
	var comp CompletedGroupElement
	var e ExtendedGroupElement

	out.Zero()

	for _, byte := range k {
		for bitNum := uint(8); bitNum > 0; bitNum-- {
			tmpP.ToCached(&cach)
			geAdd(&comp, out, &cach)

			comp.ToExtended(&e)
			ExtendedGroupElementCMove(out, &e, int32((byte>>(8-bitNum))&1))

			tmpP.Double(&comp)
			comp.ToExtended(&tmpP)
		}
	}
}

// DoubleScalarMult sets r = k*P + l*Q
// where k and l are scalars and P and Q are points
// This function is constant time
// It executes exactly 513 point additions, 512 point doublings and 512 conditional moves
func DoubleScalarMult(out *ExtendedGroupElement, k *[32]byte, p *ExtendedGroupElement, l *[32]byte, q *ExtendedGroupElement) {
	tmpP := *p
	tmpQ := *q

	var cach CachedGroupElement
	var comp CompletedGroupElement
	var e ExtendedGroupElement

	var out2 ExtendedGroupElement
	out2.Zero()
	out.Zero()

	for bix, byte := range k {
		byte2 := l[bix]
		for bitNum := uint(8); bitNum > 0; bitNum-- {
			tmpP.ToCached(&cach)
			geAdd(&comp, out, &cach)

			comp.ToExtended(&e)
			ExtendedGroupElementCMove(out, &e, int32((byte>>(8-bitNum))&1))

			tmpQ.ToCached(&cach)
			geAdd(&comp, &out2, &cach)

			comp.ToExtended(&e)
			ExtendedGroupElementCMove(&out2, &e, int32((byte2>>(8-bitNum))&1))

			tmpP.Double(&comp)
			comp.ToExtended(&tmpP)

			tmpQ.Double(&comp)
			comp.ToExtended(&tmpQ)
		}
	}

	out2.ToCached(&cach)
	geAdd(&comp, out, &cach)
	comp.ToExtended(out)
}

// PointAdd sets r = p + q
// Where p and q are points
// This function is constant time
func PointAdd(r *CompletedGroupElement, p *ExtendedGroupElement, q *CachedGroupElement) {
	geAdd(r, p, q)
}
