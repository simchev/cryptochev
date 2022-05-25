package classical

import (
	"cryptochev/utils"
	"math/rand"
	"unicode"
)

const AlphabetL = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const AlphabetL25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
const AlphabetL36 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func buildIndexMap(alphabet string) map[rune]int {
	amap := make(map[rune]int, len(alphabet))

	for i, r := range alphabet {
		amap[r] = i
	}

	return amap
}

func ShuffleString(s string) string {
	r := []rune(s)

	rand.Shuffle(len(r), func(i, j int) {
		r[i], r[j] = r[j], r[i]
	})

	return string(r)
}

func RandomAlphabetL() string {
	return ShuffleString(AlphabetL)
}

func RandomAlphabetL25() string {
	return ShuffleString(AlphabetL25)
}

func RandomAlphabetL36() string {
	return ShuffleString(AlphabetL36)
}

func RandomLetter() rune {
	return rune(65 + rand.Intn(26))
}

func RandomRuneFromString(s string) rune {
	return []rune(s)[rand.Intn(len(s))]
}

func ToPadded(s string, width int) string {
	if len(s) % width != 0 {
		pad := width - len(s) % width
		utils.SeedRand()

		for i := 0; i < pad; i++ {
			s += string(RandomRuneFromString(s))
		}
	}

	return s
}

func ToUnpadded(s string, width int) string {
	if len(s) % width != 0 {
		s = s[:len(s) - (width - len(s) % width)]
	}

	return s
}

func ToAlpha(s string) string {
	rs := make([]rune, 0, len(s))

	for _, r := range s {
		if unicode.IsLetter(r) {
			rs = append(rs, r)
		}
	}

	return string(rs)
}

func ToAlphaNumeric(s string) string {
	rs := make([]rune, 0, len(s))

	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			rs = append(rs, r)
		}
	}

	return string(rs)
}

func ToJToI(s string) string {
	rs := []rune(s)

	for i, r := range s {
		if r == 74 || r == 106 {
			rs[i]--
		}
	}

	return string(rs)
}

func ToSpaced(s string, n int) string {
	spaced := ""

	for i := 0; i < len(s); i += n {
		end := i + n

		if end > len(s) {
			end = len(s)
		}

		spaced += s[i:end]
		spaced += " "
	}

	if len(s) / n > 0 {
		spaced = spaced[0:len(spaced) - 1]
	} else {
		spaced = s
	}

	return spaced
}

func triangleNumber(n int) int {
	sum := 0
	for i := n; i > 0; i-- {
		sum += i
	}
	return sum
}