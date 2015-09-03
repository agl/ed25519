// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// func FeCMove(f, g *FieldElement, b int32)
TEXT ·FeCMove(SB),NOSPLIT,$0
	MOVQ f+0(FP), AX 
	MOVQ g+8(FP), BX 
	MOVL b+16(FP), CX

	MOVQ 0(BX),R11
	MOVQ 8(BX),R12
	MOVQ 16(BX),R13
	MOVQ 24(BX),R14
	MOVQ 32(BX),R15
	
	MOVQ $0,DX
	CMPQ DX, CX
	CMOVQEQ 0(AX), R11
	CMOVQEQ 8(AX), R12
	CMOVQEQ 16(AX),R13
	CMOVQEQ 24(AX),R14
	CMOVQEQ 32(AX),R15
	
	MOVQ R11,0(AX)
	MOVQ R12,8(AX)
	MOVQ R13,16(AX)
	MOVQ R14,24(AX)
	MOVQ R15,32(AX)
	RET
