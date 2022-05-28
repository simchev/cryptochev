package classical

import (
	"cryptochev/utils"
	"math"
	"math/rand"
	"unicode"
)

func NewSubstitute(text []rune, key *KeySubstitute) *Substitute {
	return &Substitute{Cipher: &CipherClassical[KeySubstitute]{Text: text, Key: key}}
}

type KeySubstitute struct {
	Alphabet []rune
	SAlphabet []rune
}

type Substitute struct { Cipher *CipherClassical[KeySubstitute] }
func (c *Substitute) GetText() []rune { return c.Cipher.Text }
func (c *Substitute) GetErrors() []error { return c.Cipher.Errors }
func (c *Substitute) Encrypt() { c.Cipher.Text = substitute(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.SAlphabet) }
func (c *Substitute) Decrypt() { c.Cipher.Text = substitute(c.Cipher.Text, c.Cipher.Key.SAlphabet, c.Cipher.Key.Alphabet) }
func (c *Substitute) Verify() bool { return true }

func substitute(s []rune, alphabet []rune, salphabet []rune) []rune {
	result := make([]rune, len(s))
	amap := buildIndexMap(alphabet)

	for i, r := range s {
		result[i] = salphabet[amap[r]]
	}

	return result
}

func NewShift(text []rune, key *KeyShift) *Shift {
	return &Shift{Cipher: &CipherClassical[KeyShift]{Text: text, Key: key}}
}

type KeyShift struct { Shift int }
type Shift struct { Cipher *CipherClassical[KeyShift] }
func (c *Shift) GetText() []rune { return c.Cipher.Text }
func (c *Shift) GetErrors() []error { return c.Cipher.Errors }
func (c *Shift) Encrypt() { c.Cipher.Text = shift(c.Cipher.Text, c.Cipher.Key.Shift) }
func (c *Shift) Decrypt() { c.Cipher.Text = shift(c.Cipher.Text, -c.Cipher.Key.Shift) }
func (c *Shift) Verify() bool { return true }

func shift(s []rune, shift int) []rune {
	rshift := rune(shift)

	for i, r := range s {
		s[i] = r + rshift
	}

	return s
}

func NewCaesar(text []rune, key *KeyCaesar) *Caesar {
	return &Caesar{Cipher: &CipherClassical[KeyCaesar]{Text: text, Key: key}}
}

type KeyCaesar struct { Shift int }
type Caesar struct { Cipher *CipherClassical[KeyCaesar] }
func (c *Caesar) GetText() []rune { return c.Cipher.Text }
func (c *Caesar) GetErrors() []error { return c.Cipher.Errors }
func (c *Caesar) Encrypt() { c.Cipher.Text = shiftAlphabet(c.Cipher.Text, c.Cipher.Key.Shift) }
func (c *Caesar) Decrypt() { c.Cipher.Text = shiftAlphabet(c.Cipher.Text, -c.Cipher.Key.Shift) }
func (c *Caesar) Verify() bool { return true }

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

func NewROT13(text []rune, key *KeyROT13) *ROT13 {
	return &ROT13{Cipher: &CipherClassical[KeyROT13]{Text: text, Key: key}}
}

type KeyROT13 struct {}
type ROT13 struct { Cipher *CipherClassical[KeyROT13] }
func (c *ROT13) GetText() []rune { return c.Cipher.Text }
func (c *ROT13) GetErrors() []error { return c.Cipher.Errors }
func (c *ROT13) Encrypt() { c.Cipher.Text = shiftAlphabet(c.Cipher.Text, 13) }
func (c *ROT13) Decrypt() { c.Cipher.Text = shiftAlphabet(c.Cipher.Text, 13) }
func (c *ROT13) Verify() bool { return true }

func NewVigenere(text []rune, key *KeyVigenere) *Vigenere {
	return &Vigenere{Cipher: &CipherClassical[KeyVigenere]{Text: text, Key: key}}
}

type KeyVigenere struct {
	Alphabet []rune
	Key []rune
}

type Vigenere struct { Cipher *CipherClassical[KeyVigenere] }
func (c *Vigenere) GetText() []rune { return c.Cipher.Text }
func (c *Vigenere) GetErrors() []error { return c.Cipher.Errors }
func (c *Vigenere) Encrypt() { c.Cipher.Text = cryptVigenere(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Key, true) }
func (c *Vigenere) Decrypt() { c.Cipher.Text = cryptVigenere(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Key, false) }
func (c *Vigenere) Verify() bool { return true }

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

func NewVigenereBeaufort(text []rune, key *KeyVigenere) *VigenereBeaufort {
	return &VigenereBeaufort{Cipher: &CipherClassical[KeyVigenere]{Text: text, Key: key}}
}

type VigenereBeaufort struct { Cipher *CipherClassical[KeyVigenere] }
func (c *VigenereBeaufort) GetText() []rune { return c.Cipher.Text }
func (c *VigenereBeaufort) GetErrors() []error { return c.Cipher.Errors }
func (c *VigenereBeaufort) Encrypt() { c.Cipher.Text = cryptVigenere(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Key, false) }
func (c *VigenereBeaufort) Decrypt() { c.Cipher.Text = cryptVigenere(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Key, true) }
func (c *VigenereBeaufort) Verify() bool { return true }

func gronsfeldToVigenereKey(alphabet []rune, key []rune) []rune {
	keyv := make([]rune, 0, len(key))

	for _, r := range key {
		if unicode.IsDigit(r) {
			keyv = append(keyv, alphabet[r - '0'])
		}
	}

	return keyv
}

func NewVigenereGronsfeld(text []rune, key *KeyVigenere) *VigenereGronsfeld {
	return &VigenereGronsfeld{Cipher: &CipherClassical[KeyVigenere]{Text: text, Key: key}}
}

type VigenereGronsfeld struct { Cipher *CipherClassical[KeyVigenere] }
func (c *VigenereGronsfeld) GetText() []rune { return c.Cipher.Text }
func (c *VigenereGronsfeld) GetErrors() []error { return c.Cipher.Errors }
func (c *VigenereGronsfeld) Encrypt() { c.Cipher.Text = cryptVigenere(c.Cipher.Text, c.Cipher.Key.Alphabet, gronsfeldToVigenereKey(c.Cipher.Key.Alphabet, c.Cipher.Key.Key), true) }
func (c *VigenereGronsfeld) Decrypt() { c.Cipher.Text = cryptVigenere(c.Cipher.Text, c.Cipher.Key.Alphabet, gronsfeldToVigenereKey(c.Cipher.Key.Alphabet, c.Cipher.Key.Key), false) }
func (c *VigenereGronsfeld) Verify() bool { return true }

func NewAutokey(text []rune, key *KeyAutokey) *Autokey {
	return &Autokey{Cipher: &CipherClassical[KeyAutokey]{Text: text, Key: key}}
}

type KeyAutokey struct {
	Alphabet []rune
	Primer []rune
}

type Autokey struct { Cipher *CipherClassical[KeyAutokey] }
func (c *Autokey) GetText() []rune { return c.Cipher.Text }
func (c *Autokey) GetErrors() []error { return c.Cipher.Errors }
func (c *Autokey) Encrypt() { c.Cipher.Text = cryptVigenere(c.Cipher.Text, c.Cipher.Key.Alphabet, append(c.Cipher.Key.Primer, c.Cipher.Text...), true) }
func (c *Autokey) Decrypt() { c.Cipher.Text = decryptAutokey(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Primer) }
func (c *Autokey) Verify() bool { return true }

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

func NewPlayfair(text []rune, key *KeyPlayfair) *Playfair {
	return &Playfair{Cipher: &CipherClassical[KeyPlayfair]{Text: text, Key: key}}
}

type KeyPlayfair struct {
	Alphabet []rune
	Null rune
}

type Playfair struct { Cipher *CipherClassical[KeyPlayfair] }
func (c *Playfair) GetText() []rune { return c.Cipher.Text }
func (c *Playfair) GetErrors() []error { return c.Cipher.Errors }
func (c *Playfair) Encrypt() { c.Cipher.Text = cryptPlayfair(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Null, true) }
func (c *Playfair) Decrypt() { c.Cipher.Text = cryptPlayfair(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Null, false) }
func (c *Playfair) Verify() bool { return true }

func cryptPlayfair(s []rune, alphabet []rune, null rune, encrypt bool) []rune {
	result := make([]rune, len(s), len(s) + 1)
	width := int(math.Sqrt(float64(len(alphabet))))
	amap := buildIndexMap(alphabet)
	inc, _ := utils.ReverseIf(-1, 1, encrypt)

	if len(s) % 2 != 0 {
		result = append(result, null)
	}

	for i := 0; i < len(s); i += 2 {
		i1 := amap[s[i]]
		i2 := amap[null]
		
		if i != len(s) - 1 && i1 != amap[s[i + 1]] { // NEED TO MAKE IT APPEND INSTEAD OF REPLACING
			i2 = amap[s[i + 1]]
		} else if null == 0 {
			i2 = amap[alphabet[rand.Intn(len(alphabet))]]
		}

		row1 := i1 / width
		col1 := i1 % width
		row2 := i2 / width
		col2 := i2 % width

		if row1 == row2 {
			result[i] = alphabet[(col1 + inc + width) % width + row1 * width]
			result[i + 1] = alphabet[(col2 + inc + width) % width + row2 * width]
		} else if col1 == col2 {
			result[i] = alphabet[col1 + (row1 + inc + width) % width * width]
			result[i + 1] = alphabet[col2 + (row2 + inc + width) % width * width]
		} else {
			result[i] = alphabet[col2 + row1 * width]
			result[i + 1] = alphabet[col1 + row2 * width]
		}
	}

	return result
}
