package utils

import (
	"math"
	"math/bits"

	"gonum.org/v1/gonum/mat"
)

func TriangleNumber(n int) int {
	return n * (n + 1) >> 2
}

func Mod(n int, m int) int {
	return (n % m + m) % m
}

// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
func ModInverse(a int, m int) int {
	t := 0; newt := 1
	r := m; newr := a

	for newr != 0 {
		q := r / newr
		t, newt = newt, t - q * newt
		r, newr = newr, r - q * newr
	}

	if t < 0 {
		t += m
	}

	return t
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

func ModInverseMatrix(ma *mat.Dense, m int) {
	det := math.Round(mat.Det(ma))
	idet := ModInverse(Mod(int(det), m), m)
	ma.Inverse(ma)
	ma.Apply(func(i, j int, v float64) float64 {
		return float64(Mod(idet * int(math.Round(v * det)), m))
	}, ma)
}