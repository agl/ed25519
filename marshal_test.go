package ed25519

import (
	"crypto/rand"
	"testing"

	"github.com/agl/ed25519/edwards25519"
)

func TestUnmarshalMarshal(t *testing.T) {
	pk, _, _ := GenerateKey(rand.Reader)

	var A edwards25519.ExtendedGroupElement
	ret := A.FromBytes(pk)

	var pk2 [32]byte
	A.ToBytes(&pk2)

	if *pk != pk2 {
		_ = ret
		t.Errorf("FromBytes(%v)->ToBytes not idempotent:\n%x\nbytes:\n\t%x\n\t%x\ndelta: %x\n", ret, A, *pk, pk2, int(pk[31])-int(pk2[31]))
	}
}

func TestUnmarshalMarshalTwice(t *testing.T) {
	pk, _, _ := GenerateKey(rand.Reader)

	var A edwards25519.ExtendedGroupElement
	A.FromBytes(pk)

	var pk2 [32]byte
	A.ToBytes(&pk2)

	var B edwards25519.ExtendedGroupElement
	ret := B.FromBytes(&pk2)

	var pk3 [32]byte
	B.ToBytes(&pk3)

	if *pk != pk3 {
		t.Errorf("FromBytes(%v)->ToBytes not idempotent:\n%x\nbytes:\n\t%x\n\t%x\ndelta: %x\n", ret, A, *pk, pk3, int(pk[31])-int(pk2[31]))
	}
}

func TestUnmarshalMarshalNegative(t *testing.T) {
	pk, _, _ := GenerateKey(rand.Reader)

	var A edwards25519.ExtendedGroupElement
	ret := A.FromBytes(pk)

	var pk2 [32]byte
	A.ToBytes(&pk2)
	pk2[31] ^= 0x80

	if *pk == pk2 {
		t.Errorf("flipping sign did not change public key:\n%x\nbytes:\n\t%x\n\t%x\ndelta: %x\n", ret, A, *pk, pk2, int(pk[31])-int(pk2[31]))
	}
}
