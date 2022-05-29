package utils

import (
	"math/bits"
)

func TriangleNumber(n int) int {
	return n * (n + 1) >> 2
}

// https://en.wikipedia.org/wiki/Binary_GCD_algorithm
func BinaryGCD(a uint, b uint) uint {
	if a == 0 {
		return b
	} else if b == 0 {
		return a
	}

	i := bits.TrailingZeros(a); a >>= i
	j := bits.TrailingZeros(b); b >>= j
	k, _ := SwapIf(i, j, j < i)

	for {
		a, b = SwapIf(a, b, b > a)
		a -= b

		if a == 0 {
			return b << k
		}

		a >>= bits.TrailingZeros(a)
	}
}

func IsCoprime(a uint, b uint) bool {
	if a < 2 || b < 2 {
		return a == 1 || b == 1
	}

	i := bits.TrailingZeros(a); 
	j := bits.TrailingZeros(b);
	if i > 0 && j > 0 {
		return false
	}

	a >>= i; b >>= j
	for {
		a, b = SwapIf(a, b, b > a)
		a -= b

		if a == 0 {
			return b == 1
		}

		a >>= bits.TrailingZeros(a)
	}
}

func Coprimes(n int) []int {
	sn := make([]int, 0, 100)
	sn = append(sn, 1)
	for i := 2; i < n; i++ {
		if IsCoprime(uint(i), uint(n)) {
			sn = append(sn, i)
		}
	}

	return sn
}