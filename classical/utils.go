package classical

import (
	"cryptochev/utils"
	"math"
	"math/rand"
	"unicode"
	"unicode/utf8"
)

const AlphabetL = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const AlphabetL25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
const AlphabetL36 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func ShuffleString(s string) string {
	rs := []rune(s)

	rand.Shuffle(len(rs), func(i, j int) {
		rs[i], rs[j] = rs[j], rs[i]
	})

	return string(rs)
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
	rs := []rune(s)
	return rs[rand.Intn(len(rs))]
}

func ToPadded(s string, width int) string {
	rs := []rune(s)
	rpad := make([]rune, 0, width)

	if len(rs) % width != 0 {
		pad := width - len(rs) % width
		utils.SeedRand()

		for i := 0; i < pad; i++ {
			rpad = append(rpad, RandomRuneFromString(s))
		}
	}

	return string(append(rs, rpad...))
}

func ToUnpadded(s string, width int) string {
	rs := []rune(s)

	if len(rs) % width != 0 {
		rs = rs[:len(rs) - (width - len(rs) % width)]
	}

	return string(rs)
}

func ToAlpha(s string) string {
	rs := []rune(s)
	result := make([]rune, 0, utf8.RuneCountInString(s))

	for _, r := range rs {
		if unicode.IsLetter(r) {
			result = append(result, r)
		}
	}

	return string(result)
}

func ToAlphaNumeric(s string) string {
	rs := []rune(s)
	result := make([]rune, 0, utf8.RuneCountInString(s))

	for _, r := range rs {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			result = append(result, r)
		}
	}

	return string(result)
}

func ToJToI(s string) string {
	rs := []rune(s)

	for i, r := range rs {
		if r == 74 || r == 106 {
			rs[i]--
		}
	}

	return string(rs)
}

func ToSpaced(s string, n int) string {
	rs := []rune(s)

	if len(rs) == 0 {
		return s
	}

	result := make([]rune, 0, len(rs) + int(math.Ceil(float64(len(rs)) / float64(n))))

	for i := 0; i < len(rs); i += n {
		end := i + n

		if end > len(rs) {
			end = len(rs)
		}

		result = append(result, rs[i:end]...)
		result = append(result, ' ')
	}

	return string(result[0:len(result)-1])
}

func triangleNumber(n int) int {
	sum := 0
	for i := n; i > 0; i-- {
		sum += i
	}
	return sum
}

func buildIndexMap(alphabet string) map[rune]int {
	ralphabet := []rune(alphabet)
	amap := make(map[rune]int, len(ralphabet))

	for i, r := range ralphabet {
		amap[r] = i
	}

	return amap
}