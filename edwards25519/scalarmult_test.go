package edwards25519

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"
	"math/big"
	"testing"
)

type basicPoint struct {
	x, y *big.Int
}

func (b basicPoint) Equals(o basicPoint) bool {
	return b.x.Cmp(o.x) == 0 && b.y.Cmp(o.y) == 0
}

func (b basicPoint) String() string {
	return fmt.Sprintf("(x=%s y=%s)", b.x.String(), b.y.String())
}

func (ge *CompletedGroupElement) toBasicPoint() basicPoint {
	var ge2 ExtendedGroupElement
	ge.ToExtended(&ge2)
	return ge2.toBasicPoint()
}

func (ge *ExtendedGroupElement) toBasicPoint() basicPoint {
	var q ProjectiveGroupElement
	ge.ToProjective(&q)
	return q.toBasicPoint()
}

func (ge *ProjectiveGroupElement) toBasicPoint() basicPoint {
	var recip, x, y FieldElement
	FeInvert(&recip, &ge.Z)
	FeMul(&x, &ge.X, &recip)
	FeMul(&y, &ge.Y, &recip)

	return basicPoint{
		x: x.feToBasicInt(),
		y: y.feToBasicInt(),
	}
}

var two = big.NewInt(2)

var entries = [10]*big.Int{
	big.NewInt(1),
	new(big.Int).Exp(two, big.NewInt(26), nil),
	new(big.Int).Exp(two, big.NewInt(51), nil),
	new(big.Int).Exp(two, big.NewInt(77), nil),
	new(big.Int).Exp(two, big.NewInt(102), nil),
	new(big.Int).Exp(two, big.NewInt(128), nil),
	new(big.Int).Exp(two, big.NewInt(153), nil),
	new(big.Int).Exp(two, big.NewInt(179), nil),
	new(big.Int).Exp(two, big.NewInt(204), nil),
	new(big.Int).Exp(two, big.NewInt(230), nil),
}

func (fe FieldElement) feToBasicInt() *big.Int {
	res := new(big.Int)

	res.Add(res, big.NewInt(int64(fe[0])))

	val := big.NewInt(int64(fe[1]))
	res.Add(res, val.Mul(val, entries[1]))

	val = big.NewInt(int64(fe[2]))
	res.Add(res, val.Mul(val, entries[2]))

	val = big.NewInt(int64(fe[3]))
	res.Add(res, val.Mul(val, entries[3]))

	val = big.NewInt(int64(fe[4]))
	res.Add(res, val.Mul(val, entries[4]))

	val = big.NewInt(int64(fe[5]))
	res.Add(res, val.Mul(val, entries[5]))

	val = big.NewInt(int64(fe[6]))
	res.Add(res, val.Mul(val, entries[6]))

	val = big.NewInt(int64(fe[7]))
	res.Add(res, val.Mul(val, entries[7]))

	val = big.NewInt(int64(fe[8]))
	res.Add(res, val.Mul(val, entries[8]))

	val = big.NewInt(int64(fe[9]))
	res.Add(res, val.Mul(val, entries[9]))

	return res
}

func bigIntFromString(s string) *big.Int {
	v := new(big.Int)
	v.SetString(s, 10)
	return v
}

var basePointPythonRepr = [32]byte{88, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102}
var twoTimesBasePointPythonRepr = [32]byte{201, 163, 248, 106, 174, 70, 95, 14, 86, 81, 56, 100, 81, 15, 57, 151, 86, 31, 162, 201, 232, 94, 162, 29, 194, 41, 35, 9, 243, 205, 96, 34}
var tenTimesBasePointPythonRepr = [32]byte{44, 123, 232, 106, 176, 116, 136, 186, 67, 232, 224, 61, 133, 166, 118, 37, 207, 191, 152, 200, 84, 77, 228, 200, 119, 36, 27, 122, 170, 252, 127, 227}

var identityPoint = basicPoint{
	x: bigIntFromString("0"),
	y: bigIntFromString("1"),
}

var basePoint = basicPoint{
	x: bigIntFromString("15112221349535400772501151409588531511454012693041857206046113283949847762202"),
	y: bigIntFromString("-11579208923731619542357098500868790785326998466564056403945758400791312963989"),
}

var basePointDouble = basicPoint{
	x: bigIntFromString("24727413235106541002554574571675588834622768167397638456726423682521233608206"),
	y: bigIntFromString("15549675580280190176352668710449542251549572066445060580507079593062643049417"),
}

var basePointTimesTen = basicPoint{
	x: bigIntFromString("-14395431370414769925664470432542938807701137891460107902580529290527291999902"),
	y: bigIntFromString("-12890939195558280474289675733195941537855306620467840655497321222564730078401"),
}

func printInGoFormat(repr [32]byte) string {
	var b ExtendedGroupElement
	b.FromBytes(&repr)
	return b.toBasicPoint().String()
}

func randomPoint(r *ExtendedGroupElement) {
	buffer := new([32]byte)

	io.ReadFull(rand.Reader, buffer[:])
	h := sha512.New()
	h.Write(buffer[:])
	digest := h.Sum(nil)
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var hBytes [32]byte
	copy(hBytes[:], digest)
	GeScalarMultBase(r, &hBytes)
}

var basePointE ExtendedGroupElement
var basePointP ProjectiveGroupElement
var basePointC CachedGroupElement
var basePointBasic basicPoint

func init() {
	one := [32]byte{1}
	GeScalarMultBase(&basePointE, &one)
	basePointE.ToProjective(&basePointP)
	basePointE.ToCached(&basePointC)
	basePointBasic = basePointE.toBasicPoint()
}

func TestSanityChecksOfExistingLibrary(t *testing.T) {
	var b ExtendedGroupElement
	var rc CompletedGroupElement

	zero := [32]byte{}
	GeScalarMultBase(&b, &zero)
	if !b.toBasicPoint().Equals(identityPoint) {
		t.Fatalf("GeScalarMultBase(0) should generate the identity point, was: %s", b.toBasicPoint())
	}

	one := [32]byte{1}
	GeScalarMultBase(&b, &one)
	if !b.toBasicPoint().Equals(basePoint) {
		t.Fatalf("GeScalarMultBase(1) should generate the base point, was: %s", b.toBasicPoint())
	}

	res := b.FromBytes(&basePointPythonRepr)
	if !res || !b.toBasicPoint().Equals(basePoint) {
		t.Fatalf("FromBytes([python representation of base point]) should generate the base point, was: %s", b.toBasicPoint())
	}

	two := [32]byte{2}
	GeScalarMultBase(&b, &two)
	if !b.toBasicPoint().Equals(basePointDouble) {
		t.Fatalf("GeScalarMultBase(2) should generate the double base point, was: %s", b.toBasicPoint())
	}

	ten := [32]byte{10}
	GeScalarMultBase(&b, &ten)
	if !b.toBasicPoint().Equals(basePointTimesTen) {
		t.Fatalf("GeScalarMultBase(10) should generate the base point times ten, was: %s", b.toBasicPoint())
	}

	basePointE.Double(&rc)
	rc.ToExtended(&b)
	if !b.toBasicPoint().Equals(basePointDouble) {
		t.Fatalf("basePoint.Double() should generate the double base point, was: %s", b.toBasicPoint())
	}
}

func TestPointAdd(t *testing.T) {
	var res CompletedGroupElement
	var res2 CompletedGroupElement
	var res2e ExtendedGroupElement
	PointAdd(&res, &basePointE, &basePointC)
	if !res.toBasicPoint().Equals(basePointDouble) {
		t.Fatalf("PointAdd(basePoint, basePoint) should generate the double base point, but was: %s vs %s", res.toBasicPoint(), basePointDouble)
	}

	var rp1 ExtendedGroupElement
	var rp2 ExtendedGroupElement
	var rpC CachedGroupElement

	randomPoint(&rp1)
	randomPoint(&rp2)
	rp1.ToCached(&rpC)

	PointAdd(&res, &rp1, &rpC)
	rp1.Double(&res2)
	if !res.toBasicPoint().Equals(res2.toBasicPoint()) {
		t.Fatalf("PointAdd(P, P) should generate the same result as Double(P), but was: %s vs %s", res.toBasicPoint(), res2.toBasicPoint())
	}

	two := [32]byte{2}
	ScalarMult(&res2e, &two, &rp1)
	if !res.toBasicPoint().Equals(res2e.toBasicPoint()) {
		t.Fatalf("PointAdd(P, P) should generate the same result as ScalarMult(2, P), but was: %s vs %s", res.toBasicPoint(), res2e.toBasicPoint())
	}

	PointAdd(&res, &basePointE, &basePointC)
	GeScalarMultBase(&res2e, &two)
	if !res.toBasicPoint().Equals(res2e.toBasicPoint()) {
		t.Fatalf("PointAdd(B, B) should generate the same result as ScalarMultBase(2), but was: %s vs %s", res.toBasicPoint(), res2e.toBasicPoint())
	}
}

func TestDoubleScalarMult(t *testing.T) {
	var rp1 ExtendedGroupElement
	var res1 ProjectiveGroupElement
	var res2 ExtendedGroupElement
	randomPoint(&rp1)

	arg1 := [32]byte{191, 167, 168, 36, 214, 101, 140, 153, 31, 174, 240, 131, 178, 220, 4, 23, 63, 200, 108, 79, 122, 145, 143, 45, 141, 223, 182, 43, 28, 133, 60, 120}
	arg2 := [32]byte{61, 88, 82, 173, 35, 82, 196, 75, 120, 174, 211, 66, 42, 24, 210, 222, 3, 6, 129, 133, 116, 121, 56, 54, 253, 101, 140, 238, 19, 208, 54, 122}

	GeDoubleScalarMultVartime(&res1, &arg1, &rp1, &arg2)
	DoubleScalarMult(&res2, &arg1, &rp1, &arg2, &basePointE)

	if !res1.toBasicPoint().Equals(res2.toBasicPoint()) {
		t.Fatalf("GeDoubleScalarMultVartime(k, P, q) should generate the same result as DoubleScalarMult(k, P, q, B), but was: %s vs %s", res1.toBasicPoint(), res2.toBasicPoint())
	}

	arg2 = [32]byte{0}

	GeDoubleScalarMultVartime(&res1, &arg1, &rp1, &arg2)
	DoubleScalarMult(&res2, &arg1, &rp1, &arg2, &basePointE)

	if !res1.toBasicPoint().Equals(res2.toBasicPoint()) {
		t.Fatalf("GeDoubleScalarMultVartime(k, P, 0) should generate the same result as DoubleScalarMult(k, P, 0, B), but was: %s vs %s", res1.toBasicPoint(), res2.toBasicPoint())
	}
}

func TestScalarMult(t *testing.T) {
	var rp1 ExtendedGroupElement
	var res1p ProjectiveGroupElement
	var res1e ExtendedGroupElement
	var res2 ExtendedGroupElement
	randomPoint(&rp1)

	arg1 := [32]byte{191, 167, 168, 36, 214, 101, 140, 153, 31, 174, 240, 131, 178, 220, 4, 23, 63, 200, 108, 79, 122, 145, 143, 45, 141, 223, 182, 43, 28, 133, 60, 120}
	arg2 := [32]byte{0}

	GeDoubleScalarMultVartime(&res1p, &arg1, &rp1, &arg2)
	ScalarMult(&res2, &arg1, &rp1)

	if !res1p.toBasicPoint().Equals(res2.toBasicPoint()) {
		t.Fatalf("GeDoubleScalarMultVartime(k, P, 0) should generate the same result as ScalarMult(k, P), but was: %s vs %s", res1p.toBasicPoint(), res2.toBasicPoint())
	}

	GeScalarMultBase(&res1e, &arg1)
	ScalarMult(&res2, &arg1, &basePointE)

	if !res1e.toBasicPoint().Equals(res2.toBasicPoint()) {
		t.Fatalf("GeScalarMultBase(k) should generate the same result as ScalarMult(k, B), but was: %s vs %s", res1e.toBasicPoint(), res2.toBasicPoint())
	}
}
