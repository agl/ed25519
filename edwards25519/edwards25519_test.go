package edwards25519_test

import (
	"math/rand"
	"testing"

	"github.com/bwesterb/ed25519/edwards25519"
)

func TestRistretto(t *testing.T) {
	var ge edwards25519.ExtendedGroupElement
	var buf [32]byte
	var buf2 [32]byte

	for i := 0; i < 10000; i++ {
		rand.Read(buf[:])
		buf[31] &= 127 // clear highest bit
		if !ge.FromRistrettoBytes(&buf) {
			continue
		}
		ge.ToRistrettoBytes(&buf2)
		if buf != buf2 {
			t.Fatalf("ToRistrettoBytes(FromRistrettoBytes(x)) != x, (%v != %v)", buf2, buf)
		}
	}
}
