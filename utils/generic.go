package utils

func Contains[T comparable](s []T, e T) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

func IndexOf[T comparable](collection []T, el T) int {
	for i, x := range collection {
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