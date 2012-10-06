// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ed25519 implements the Ed25519 signature algorithm. See
// http://ed25519.cr.yp.to/.
package ed25519

import (
	"bytes"
	"crypto/sha512"
	"io"
	"math/big"
)

const (
	PublicKeySize = 32
	PrivateKeySize = 64
	SignatureSize = 64
)

var (
	// p25519 is 2**255-19, a prime number.
	p25519 *big.Int
	// n25521 is p-2 = 2**255-21.
	n25521 *big.Int
	// n2523 is (p-5)/8 = 2**252-3
	n2523 *big.Int
	// sqrtm1 is sqrt(-1) mod p
	sqrtm1 *big.Int
	// order is the order of the Twisted Edward's group: 2**252 + 27742317777372353535851937790883648493.
	order *big.Int
	// d is -121665/121666 mod 2**255-19, a parameter of the Twisted Edward's curve.
	d *big.Int
	// k is 2*d mod 2**255-19
	k *big.Int
	// (bX, bY) is the base point of the curve.
	bX, bY *big.Int
	bigOne *big.Int
)

func init() {
	p25519, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	n25521, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb", 16)
	n2523, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd", 16)
	sqrtm1, _ = new(big.Int).SetString("2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0", 16)
	d, _ = new(big.Int).SetString("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", 16)
	k, _ = new(big.Int).SetString("2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159", 16)
	bX, _ = new(big.Int).SetString("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", 16)
	bY, _ = new(big.Int).SetString("6666666666666666666666666666666666666666666666666666666666666658", 16)
	order, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	bigOne = big.NewInt(1)
}

// invert sets out = a^{-1} mod 2**255-19 by raising to the power of p-2 (see
// Fermat's Little Theorem).
func invert(out, a *big.Int) {
	out.Exp(a, n25521, p25519)
}

// context is used to provide a pool of allocated big.Int's for use during
// scalar multiplication.
type context struct {
	t1, t2, t3, t4, t5, t6, t7, t8 *big.Int
}

func newContext() *context {
	return &context{
		t1: new(big.Int),
		t2: new(big.Int),
		t3: new(big.Int),
		t4: new(big.Int),
		t5: new(big.Int),
		t6: new(big.Int),
		t7: new(big.Int),
		t8: new(big.Int),
	}
}

// GenerateKey generates a public/private key pair using randomness from rand.
func GenerateKey(rand io.Reader) (publicKey *[PublicKeySize]byte, privateKey *[PrivateKeySize]byte, err error) {
	privateKey = new([64]byte)
	publicKey = new([32]byte)
	_, err = io.ReadFull(rand, privateKey[:32])
	if err != nil {
		return nil, nil, err
	}

	h := sha512.New()
	h.Write(privateKey[:32])
	digest := h.Sum(nil)

	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64
	a := scalarFrom32Bytes(digest[:32])
	Ax, Ay := newContext().scalarMult(a, bX, bY).toAffine()
	encodePoint(publicKey, Ax, Ay)

	copy(privateKey[32:], publicKey[:])
	return
}

// a fieldElement is a point on the Twisted Edward's curve represented in
// extended coordinates. An affine point (x', y') is encoded as x = x'/z,
// y = y'/z, t = x'y'/z.
type fieldElement struct {
	x, y, z, t *big.Int
}

func newFieldElement() *fieldElement {
	return &fieldElement{
		x: new(big.Int),
		y: new(big.Int),
		z: new(big.Int),
		t: new(big.Int),
	}
}

// toAffine converts from extended coordinates to affine coordinates.
func (fe *fieldElement) toAffine() (x, y *big.Int) {
	zInv := new(big.Int)
	invert(zInv, fe.z)
	x = new(big.Int).Mul(zInv, fe.x)
	x.Mod(x, p25519)
	y = new(big.Int).Mul(zInv, fe.y)
	y.Mod(y, p25519)
	return
}

// pointAdd adds two curve points, a and b, and puts a+b into out.
// See http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
func (c *context) pointAdd(out, a, b *fieldElement) {
	c.t1.Sub(a.y, a.x)
	if c.t1.Sign() < 0 {
		c.t1.Add(c.t1, p25519)
	}
	c.t2.Sub(b.y, b.x)
	if c.t2.Sign() < 0 {
		c.t2.Add(c.t2, p25519)
	}
	c.t1.Mul(c.t1, c.t2) // A

	c.t2.Add(a.y, a.x)
	c.t3.Add(b.y, b.x)
	c.t2.Mul(c.t2, c.t3) // B

	c.t3.Mul(a.t, b.t)
	c.t3.Mul(c.t3, k) // C

	c.t4.Mul(a.z, b.z)
	c.t4.Lsh(c.t4, 1) // D

	c.t5.Sub(c.t2, c.t1) // E
	if c.t5.Sign() < 0 {
		c.t5.Add(c.t5, p25519)
	}

	c.t6.Sub(c.t4, c.t3) // F
	if c.t6.Sign() < 0 {
		c.t6.Add(c.t6, p25519)
	}

	c.t7.Add(c.t4, c.t3) // G
	c.t8.Add(c.t1, c.t2) // H

	out.x.Mul(c.t5, c.t6)
	out.x.Mod(out.x, p25519)
	out.y.Mul(c.t7, c.t8)
	out.y.Mod(out.y, p25519)
	out.t.Mul(c.t5, c.t8)
	out.t.Mod(out.t, p25519)
	out.z.Mul(c.t6, c.t7)
	out.z.Mod(out.z, p25519)
}

// scalarMult calculates scalar*(px, py) and returns the result in extended
// coordinates.
func (c *context) scalarMult(scalar, px, py *big.Int) *fieldElement {
	scalarBytes := scalar.Bytes()
	n := newFieldElement()
	p := newFieldElement()
	p.x.Set(px)
	p.y.Set(py)
	p.z.SetInt64(1)
	p.t.Mul(p.x, p.y)
	n.x.SetInt64(0)
	n.y.SetInt64(1)
	n.z.SetInt64(1)
	n.t.SetInt64(0)

	for _, x := range scalarBytes {
		for bit := 0; bit < 8; bit++ {
			c.pointAdd(n, n, n)
			if x&0x80 != 0 {
				c.pointAdd(n, n, p)
			}
			x <<= 1
		}
	}

	return n
}

// encodePoint encodes a point on the curve into 32 bytes by encoding the y
// coordinate in the first 255 bits, followed by the parity of the
// x-coordinate.
func encodePoint(out *[32]byte, px, py *big.Int) {
	b := py.Bytes()
	for i := range b {
		out[i] = b[len(b)-(1+i)]
	}
	if px.Bit(0) == 1 {
		out[31] |= 0x80
	}
}

// scalarFrom64Bytes interprets v as a 64-byte, little-endian number and
// returns an element of the scalar field.
func scalarFrom64Bytes(v []byte) *big.Int {
	// math.big takes bytes in big-endian form so we have to reverse the
	// bytes.
	var reversedBytes [64]byte
	for i := 0; i < 64; i++ {
		reversedBytes[i] = v[63-i]
	}
	r := new(big.Int).SetBytes(reversedBytes[:])
	r.Mod(r, order)
	return r
}

// scalarFrom32Bytes interprets v as a 32-byte, little-endian number and
// returns an element of the scalar field.
func scalarFrom32Bytes(v []byte) *big.Int {
	// math.big takes bytes in big-endian form so we have to reverse the
	// bytes.
	var reversedBytes [32]byte
	for i := 0; i < 32; i++ {
		reversedBytes[i] = v[31-i]
	}
	n := new(big.Int).SetBytes(reversedBytes[:])
	n.Mod(n, order)
	return n
}

// encodeScalar encodes s in to out as a 32-byte, little-endian number.
func encodeScalar(out []byte, s *big.Int) {
	b := s.Bytes()
	for i := 0; i < len(b); i++ {
		out[i] = b[len(b)-(1+i)]
	}
}

// Sign signs the message with privateKey and returns a signature.
func Sign(privateKey *[PrivateKeySize]byte, message []byte) *[SignatureSize]byte {
	h := sha512.New()
	h.Write(privateKey[:32])
	var digestBytes1, digestBytes2, digestBytes3 [64]byte
	expandedSecretKey := h.Sum(digestBytes1[:0])

	expandedSecretKey[0] &= 248
	expandedSecretKey[31] &= 127
	expandedSecretKey[31] |= 64
	a := scalarFrom32Bytes(expandedSecretKey[:32])

	h.Reset()
	h.Write(expandedSecretKey[32:])
	h.Write(message)
	messageDigest := h.Sum(digestBytes2[:0])

	r := scalarFrom64Bytes(messageDigest)
	Rx, Ry := newContext().scalarMult(r, bX, bY).toAffine()
	var encodedR [32]byte
	encodePoint(&encodedR, Rx, Ry)

	h.Reset()
	h.Write(encodedR[:])
	h.Write(privateKey[32:])
	h.Write(message)
	hramDigest := h.Sum(digestBytes3[:0])
	s := scalarFrom64Bytes(hramDigest)
	s.Mul(s, a)
	s.Add(s, r)
	s.Mod(s, order)

	signature := new([64]byte)
	copy(signature[:32], encodedR[:])
	encodeScalar(signature[32:], s)
	return signature
}

// decodePoint unpacks a curve point, as encoded by encodePoint, and returns
// its affine coordinates.
func decodePoint(in *[32]byte) (x, y *big.Int, ok bool) {
	var bigEndian [32]byte
	for i := 0; i < 32; i++ {
		bigEndian[i] = in[31-i]
	}
	bigEndian[0] &= 0x7f
	y = new(big.Int).SetBytes(bigEndian[:])

	u := new(big.Int).Mul(y, y)
	u.Mod(u, p25519)
	v := new(big.Int).Set(u)
	u.Sub(u, bigOne)
	if u.Sign() < 0 {
		u.Add(u, p25519)
	}
	v.Mul(v, d)
	v.Add(v, bigOne)
	v.Mod(v, p25519)

	v2 := new(big.Int).Mul(v, v)
	v3 := new(big.Int).Mul(v2, v)
	v3.Mod(v3, p25519)
	v4 := new(big.Int).Mul(v2, v2)
	v7 := v4.Mul(v4, v3)
	b := v7.Mul(v7, u)
	b.Mod(b, p25519)
	b.Exp(b, n2523, p25519)
	b.Mul(b, v3)
	b.Mul(b, u)
	b.Mod(b, p25519)

	check := v2.Mul(b, b)
	check.Mul(check, v)
	check.Mod(check, p25519)
	if check.Cmp(u) != 0 {
		b.Mul(b, sqrtm1)
		b.Mod(b, p25519)
		check.Mul(b, b)
		check.Mul(check, v)
		check.Mod(check, p25519)
	}

	if check.Cmp(u) != 0 {
		return nil, nil, false
	}

	if b.Bit(0) != uint(in[31]>>7) {
		b.Neg(b)
		b.Add(b, p25519)
	}

	return b, y, true
}

// Verify returns true iff sig is a valid signature of message by publicKey.
func Verify(publicKey *[PublicKeySize]byte, message []byte, sig *[SignatureSize]byte) bool {
	h := sha512.New()
	h.Write(sig[:32])
	h.Write(publicKey[:])
	h.Write(message)
	digest := h.Sum(nil)
	H := scalarFrom64Bytes(digest)
	S := scalarFrom32Bytes(sig[32:])

	Ax, Ay, ok := decodePoint(publicKey)
	if !ok {
		return false
	}

	c := newContext()
	SB := c.scalarMult(S, bX, bY)
	HRAMA := c.scalarMult(H, Ax, Ay)
	HRAMA.x.Neg(HRAMA.x)
	HRAMA.x.Add(HRAMA.x, p25519)
	HRAMA.t.Neg(HRAMA.t)
	HRAMA.t.Add(HRAMA.t, p25519)
	out := newFieldElement()
	c.pointAdd(out, SB, HRAMA)
	Px, Py := out.toAffine()

	var rPrime [32]byte
	encodePoint(&rPrime, Px, Py)
	return bytes.Equal(sig[:32], rPrime[:])
}
