package classical

import (
	"cryptochev/utils"
	"math"
	"math/rand"
	"unicode"
)

const AlphabetL = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const AlphabetL25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
const AlphabetL36 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func RandomAlphabetL() []rune {
	return utils.Shuffle([]rune(AlphabetL))
}

func RandomAlphabetL25() []rune {
	return utils.Shuffle([]rune(AlphabetL25))
}

func RandomAlphabetL36() []rune {
	return utils.Shuffle([]rune(AlphabetL36))
}

func buildAlphabetKey(alphabet []rune, key []rune) ([]rune, []rune) {
	amap := buildIndexMap(alphabet)
	ukey := make([]rune, 0, len(key))
	for _, r := range key {
		_, found := amap[r]
		if found && utils.IndexOf(ukey, r) == -1 {
			ukey = append(ukey, r)
		}
	}

	remains := make([]rune, 0, len(alphabet) - len(ukey))
	for _, r := range alphabet {
		if utils.IndexOf(ukey, r) == -1 && utils.IndexOf(remains, r) == -1 {
			remains = append(remains, r)
		}
	}

	return ukey, remains
}

func AlphabetKey(alphabet []rune, key []rune) []rune {
	ukey, remains := buildAlphabetKey(alphabet, key)
	return append(ukey, remains...)
}

func RandomAlphabetKey(alphabet []rune, key []rune) []rune {
	ukey, remains := buildAlphabetKey(alphabet, key)
	return append(ukey, utils.Shuffle(remains)...)
}

func AlphabetKeyL25(key []rune) []rune {
	return AlphabetKey([]rune(AlphabetL25), key)
}

func AlphabetKeyL36(key []rune) []rune {
	return AlphabetKey([]rune(AlphabetL36), key)
}

func RandomAlphabetKeyL25(key []rune) []rune {
	return RandomAlphabetKey([]rune(AlphabetL25), key)
}

func RandomAlphabetKeyL36(key []rune) []rune {
	return RandomAlphabetKey([]rune(AlphabetL36), key)
}

func RandomLetter() rune {
	return rune(65 + rand.Intn(26))
}

func RandomRuneFrom(r []rune) rune {
	return r[rand.Intn(len(r))]
}

func ToPadded(s string, width int) string {
	rs := []rune(s)
	rpad := make([]rune, 0, width)

	if len(rs) % width != 0 {
		pad := width - len(rs) % width
		utils.SeedRand()

		for i := 0; i < pad; i++ {
			rpad = append(rpad, RandomRuneFrom(rs))
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
	result := make([]rune, 0, len(rs))

	for _, r := range rs {
		if unicode.IsLetter(r) {
			result = append(result, r)
		}
	}

	return string(result)
}

func ToAlphaNumeric(s string) string {
	rs := []rune(s)
	result := make([]rune, 0, len(rs))

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

func buildIndexMap(alphabet []rune) map[rune]int {
	amap := make(map[rune]int, len(alphabet))

	for i, r := range alphabet {
		amap[r] = i
	}

	return amap
}