// Copyright (C) 2019 ProtonTech AG
// This file contains necessary tools for the aex and ocb packages.
//
// These functions SHOULD NOT be used elsewhere, since they are optimized for
// specific input nature in the EAX and OCB modes of operation.

package byteutil

import (
	"crypto/subtle"
	"strconv"
)

// GfnDouble computes 2 * input in the field of 2^n elements.
// The irreducible polynomial in the finite field for n=128 is
// x^128 + x^7 + x^2 + x + 1 (equals 0x87)
// Constant-time execution in order to avoid side-channel attacks
func GfnDouble(input []byte) []byte {
	var p []byte
	switch len(input) {
	case 8:
		// x^64 + x^4 + x^3 + x + 1
		p = []byte{0x1B}
	case 16:
		// x^128 + x^7 + x^2 + x + 1
		p = []byte{0x87}
	case 32:
		// x^256 + x^10 + x^5 + x^2 + 1
		p = []byte{4, 0x25} // 0x425 big-endian
	case 64:
		// x^512 + x^8 + x^5 + x^2 + 1
		p = []byte{1, 0x25} // 0x125 big-endian
	case 128:
		// x^1024 + x^19 + x^6 + x + 1
		p = []byte{8, 0, 0x43} // 0x80043 big-endian
	default:
		panic("unsupported input size for GfnDouble: " + strconv.Itoa(len(input)))
	}
	// If the first bit is zero, return 2L = L << 1
	// Else return (L << 1) xor polinomial. shiftLeft(dst, src) returns the first bit.
	var shifted = make([]byte, len(input))
	v := shiftLeft(shifted, input)
	for i := 0; i < len(p); i++ {
		shifted[len(input)-len(p)+i] ^= byte(subtle.ConstantTimeSelect(v, int(p[i]), 0))
	}
	return shifted
}

func shiftLeft(dst, src []byte) int {
	var b, bit byte
	for i := len(src) - 1; i >= 0; i-- { // a range would be nice
		bit = src[i] >> 7
		dst[i] = src[i]<<1 | b
		b = bit
	}
	return int(b)
}

// XorBytesMut replaces X with X XOR Y. len(X) must be >= len(Y).
func XorBytesMut(X, Y []byte) {
	for i := 0; i < len(Y); i++ {
		X[i] ^= Y[i]
	}
}

// XorBytes puts X XOR Y into Z. len(Z) and len(X) must be >= len(Y).
func XorBytes(Z, X, Y []byte) {
	for i := 0; i < len(Y); i++ {
		Z[i] = X[i] ^ Y[i]
	}
}

// RightXor XORs smaller input (assumed Y) at the right of the larger input (assumed X)
func RightXor(X, Y []byte) []byte {
	offset := len(X) - len(Y)
	xored := make([]byte, len(X))
	copy(xored, X)
	for i := 0; i < len(Y); i++ {
		xored[offset+i] ^= Y[i]
	}
	return xored
}

// SliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func SliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
