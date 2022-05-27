package classical

import (
	"cryptochev/utils"
	"math"
	"math/rand"
	"unicode"
)

type KeySubstitute struct {
	Alphabet []rune
	SAlphabet []rune
}

type Substitute struct {
	Data *CipherClassicalData[KeySubstitute]
}

func (c *Substitute) GetText() []rune { return c.Data.Text }
func (c *Substitute) Encrypt() { c.Data.Text = substitute(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.SAlphabet) }
func (c *Substitute) Decrypt() { c.Data.Text = substitute(c.Data.Text, c.Data.Key.SAlphabet, c.Data.Key.Alphabet) }

func substitute(s []rune, alphabet []rune, salphabet []rune) []rune {
	result := make([]rune, len(s))
	amap := buildIndexMap(alphabet)

	for i, r := range s {
		result[i] = salphabet[amap[r]]
	}

	return result
}

type KeyShift int
type Shift struct {
	Data *CipherClassicalData[KeyShift]
}

func (c *Shift) GetText() []rune { return c.Data.Text }
func (c *Shift) Encrypt() { c.Data.Text = shift(c.Data.Text, int(*c.Data.Key)) }
func (c *Shift) Decrypt() { c.Data.Text = shift(c.Data.Text, -int(*c.Data.Key)) }

func shift(s []rune, shift int) []rune {
	rshift := rune(shift)

	for i, r := range s {
		s[i] = r + rshift
	}

	return s
}

type KeyCaesar int
type Caesar struct {
	Data *CipherClassicalData[KeyCaesar]
}

func (c *Caesar) GetText() []rune { return c.Data.Text }
func (c *Caesar) Encrypt() { c.Data.Text = shiftAlphabet(c.Data.Text, int(*c.Data.Key)) }
func (c *Caesar) Decrypt() { c.Data.Text = shiftAlphabet(c.Data.Text, -int(*c.Data.Key)) }

func shiftAlphabet(s []rune, shift int) []rune {
	rshift := rune(shift % 26)
	if rshift < 0 {
		rshift += 26
	}

	for i, r := range s {
		if unicode.IsUpper(r) {
			s[i] = (r + rshift - 'A') % 26 + 'A'
		} else if unicode.IsLower(r) {
			s[i] = (r + rshift - 'a') % 26 + 'a'
		}
	}

	return s
}

type KeyROT13 struct {}
type ROT13 struct {
	Data *CipherClassicalData[KeyROT13]
}

func (c *ROT13) GetText() []rune { return c.Data.Text }
func (c *ROT13) Encrypt() { c.Data.Text = shiftAlphabet(c.Data.Text, 13) }
func (c *ROT13) Decrypt() { c.Data.Text = shiftAlphabet(c.Data.Text, 13) }

type KeyVigenere struct {
	Alphabet []rune
	Key []rune
}

type Vigenere struct {
	Data *CipherClassicalData[KeyVigenere]
}

func (c *Vigenere) GetText() []rune { return c.Data.Text }
func (c *Vigenere) Encrypt() { c.Data.Text = cryptVigenere(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Key, true) }
func (c *Vigenere) Decrypt() { c.Data.Text = cryptVigenere(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Key, false) }

func cryptVigenere(s []rune, alphabet []rune, key []rune, encrypt bool) []rune {
	if len(key) == 0 {
		key = alphabet
	}

	result := make([]rune, len(s))
	amap := buildIndexMap(alphabet)
	
	for i, r := range s {
		if encrypt {
			result[i] = alphabet[(amap[r] + amap[key[i % len(key)]]) % len(alphabet)]
		} else {
			result[i] = alphabet[(amap[r] - amap[key[i % len(key)]] + len(alphabet)) % len(alphabet)]
		}
	}

	return result
}

type VigenereBeaufort struct {
	Data *CipherClassicalData[KeyVigenere]
}

func (c *VigenereBeaufort) GetText() []rune { return c.Data.Text }
func (c *VigenereBeaufort) Encrypt() { c.Data.Text = cryptVigenere(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Key, false) }
func (c *VigenereBeaufort) Decrypt() { c.Data.Text = cryptVigenere(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Key, true) }

func gronsfeldToVigenereKey(alphabet []rune, key []rune) []rune {
	keyv := make([]rune, 0, len(key))

	for _, r := range key {
		if unicode.IsDigit(r) {
			keyv = append(keyv, alphabet[r - '0'])
		}
	}

	return keyv
}

type VigenereGronsfeld struct {
	Data *CipherClassicalData[KeyVigenere]
}

func (c *VigenereGronsfeld) GetText() []rune { return c.Data.Text }
func (c *VigenereGronsfeld) Encrypt() { c.Data.Text = cryptVigenere(c.Data.Text, c.Data.Key.Alphabet, gronsfeldToVigenereKey(c.Data.Key.Alphabet, c.Data.Key.Key), true) }
func (c *VigenereGronsfeld) Decrypt() { c.Data.Text = cryptVigenere(c.Data.Text, c.Data.Key.Alphabet, gronsfeldToVigenereKey(c.Data.Key.Alphabet, c.Data.Key.Key), false) }

type KeyAutokey struct {
	Alphabet []rune
	Primer []rune
}

type Autokey struct {
	Data *CipherClassicalData[KeyAutokey]
}

func (c *Autokey) GetText() []rune { return c.Data.Text }
func (c *Autokey) Encrypt() { c.Data.Text = cryptVigenere(c.Data.Text, c.Data.Key.Alphabet, append(c.Data.Key.Primer, c.Data.Text...), true) }
func (c *Autokey) Decrypt() { c.Data.Text = decryptAutokey(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Primer) }

func decryptAutokey(s []rune, alphabet []rune, primer []rune) []rune {
	result := make([]rune, len(s))
	key := make([]rune, 0, len(s) + len(primer))
	key = append(key, primer...)
	amap := buildIndexMap(alphabet)
	
	for i, r := range s {
		result[i] = alphabet[(amap[r] - amap[key[i]] + len(alphabet)) % len(alphabet)]
		key = append(key, result[i])
	}

	return result
}

type KeyPlayfair struct {
	Alphabet []rune
	Null rune
}

type Playfair struct {
	Data *CipherClassicalData[KeyPlayfair]
}

func (c *Playfair) GetText() []rune { return c.Data.Text }
func (c *Playfair) Encrypt() { c.Data.Text = cryptPlayfair(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Null, true) }
func (c *Playfair) Decrypt() { c.Data.Text = cryptPlayfair(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Null, false) }

func cryptPlayfair(s []rune, alphabet []rune, null rune, encrypt bool) []rune {
	result := make([]rune, len(s), len(s) + 1)
	width := int(math.Sqrt(float64(len(alphabet))))
	amap := buildIndexMap(alphabet)

	if len(s) % 2 != 0 {
		result = append(result, null)
	}

	for i := 0; i < len(s); i += 2 {
		i1 := amap[s[i]]
		i2 := amap[null]
		
		if i != len(s) - 1 && i1 != amap[s[i + 1]] {
			i2 = amap[s[i + 1]]
		} else if null == 0 {
			i2 = amap[alphabet[rand.Intn(len(alphabet))]]
		}

		row1 := i1 / width
		col1 := i1 % width
		row2 := i2 / width
		col2 := i2 % width

		if row1 == row2 {
			inc, _ := utils.ReverseIf(-1, 1, encrypt)
			result[i] = alphabet[(col1 + inc + width) % width + row1 * width]
			result[i + 1] = alphabet[(col2 + inc + width) % width + row2 * width]
		} else if col1 == col2 {
			inc, _ := utils.ReverseIf(-1, 1, encrypt)
			result[i] = alphabet[col1 + (row1 + inc + width) % width * width]
			result[i + 1] = alphabet[col2 + (row2 + inc + width) % width * width]
		} else {
			result[i] = alphabet[col2 + row1 * width]
			result[i + 1] = alphabet[col1 + row2 * width]
		}
	}

	return result
}
