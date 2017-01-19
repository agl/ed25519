// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !amd64

package edwards25519

func FeCMove(f, g *FieldElement, b int32) {
	b = -b
	f[0] ^= b & (f[0] ^ g[0])
	f[1] ^= b & (f[1] ^ g[1])
	f[2] ^= b & (f[2] ^ g[2])
	f[3] ^= b & (f[3] ^ g[3])
	f[4] ^= b & (f[4] ^ g[4])
	f[5] ^= b & (f[5] ^ g[5])
	f[6] ^= b & (f[6] ^ g[6])
	f[7] ^= b & (f[7] ^ g[7])
	f[8] ^= b & (f[8] ^ g[8])
	f[9] ^= b & (f[9] ^ g[9])
}
