package utils

import "math/rand"

func Shuffle[T comparable](col []T) []T {
	rand.Shuffle(len(col), func(i, j int) {
		col[i], col[j] = col[j], col[i]
	})

	return col
}

func Contains[T comparable](s []T, e T) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

func IndexOf[T comparable](col []T, el T) int {
	for i, x := range col {
		if x == el {
			return i
		}
	}
	return -1
}

func ReverseIf[T comparable](t1 T, t2 T, c bool) (T, T) {
	if c {
		t1, t2 = t2, t1
	}
	return t1, t2
}