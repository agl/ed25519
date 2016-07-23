package edwards25519

import (
	"fmt"
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
		t.Fatalf("GeScalarMultBase(0) should generate the identity point")
	}

	one := [32]byte{1}
	GeScalarMultBase(&b, &one)
	if !b.toBasicPoint().Equals(basePoint) {
		t.Fatalf("GeScalarMultBase(1) should generate the base point")
	}

	res := b.FromBytes(&basePointPythonRepr)
	if !res || !b.toBasicPoint().Equals(basePoint) {
		t.Fatalf("FromBytes([python representation of base point]) should generate the base point")
	}

	two := [32]byte{2}
	GeScalarMultBase(&b, &two)
	if !b.toBasicPoint().Equals(basePointDouble) {
		t.Fatalf("GeScalarMultBase(2) should generate the double base point")
	}

	ten := [32]byte{10}
	GeScalarMultBase(&b, &ten)
	if !b.toBasicPoint().Equals(basePointTimesTen) {
		t.Fatalf("GeScalarMultBase(10) should generate the base point times ten")
	}

	basePointE.Double(&rc)
	rc.ToExtended(&b)
	if !b.toBasicPoint().Equals(basePointDouble) {
		t.Fatalf("basePoint.Double() should generate the double base point")
	}
}

func TestPointAdd(t *testing.T) {
	var res CompletedGroupElement
	PointAdd(&res, &basePointE, &basePointC)
	if !res.toBasicPoint().Equals(basePointDouble) {
		t.Fatalf("PointAdd(basePoint, basePoint) should generate the double base point")
	}
}

// Testing we can do:
// - Check that DoubleScalarMult returns the same result as GeDoubleScalarMultVartime when Q is the base point
// - Check that ScalarMult returns the same result as GeDoubleScalarMultVartime when b is zero
// - Check that PointAdd on the same point as P and Q returns the same as Double, and the same as ScalarMult of 2*P
// - Check that ScalarMultBase and ScalarMult returns the same results
// - Check that ScalarMultBase and an argument of 2 returns the same result as PointAdd of B with B
// - begin by testing against the python code
