package classical

import (
	"cryptochev/utils"
	"math"
	"math/rand"
	"unicode"
)

func NewKeySubstitute(alphabet []rune, salphabet []rune) *KeySubstitute { return &KeySubstitute{Alphabet: alphabet, SAlphabet: salphabet} }
func NewSubstitute(text []rune, key *KeySubstitute) *Substitute { return &Substitute{Cipher: &CipherClassical[KeySubstitute]{Text: text, Key: key}} }

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

func substitute(text []rune, alphabet []rune, salphabet []rune) []rune {
	result := make([]rune, len(text))
	amap := buildIndexMap(alphabet)

	for i, r := range text {
		result[i] = salphabet[amap[r]]
	}

	return result
}

func NewKeyShift(shift int) *KeyShift { return &KeyShift{Shift: shift} }
func NewShift(text []rune, key *KeyShift) *Shift { return &Shift{Cipher: &CipherClassical[KeyShift]{Text: text, Key: key}} }

type KeyShift struct { 
	Shift int 
}

type Shift struct { Cipher *CipherClassical[KeyShift] }
func (c *Shift) GetText() []rune { return c.Cipher.Text }
func (c *Shift) GetErrors() []error { return c.Cipher.Errors }
func (c *Shift) Encrypt() { c.Cipher.Text = shift(c.Cipher.Text, c.Cipher.Key.Shift) }
func (c *Shift) Decrypt() { c.Cipher.Text = shift(c.Cipher.Text, -c.Cipher.Key.Shift) }
func (c *Shift) Verify() bool { return true }

func shift(text []rune, shift int) []rune {
	rshift := rune(shift)

	for i, r := range text {
		text[i] = r + rshift
	}

	return text
}

func NewKeyCaesar(shift int) *KeyCaesar { return &KeyCaesar{Shift: shift} }
func NewCaesar(text []rune, key *KeyCaesar) *Caesar { return &Caesar{Cipher: &CipherClassical[KeyCaesar]{Text: text, Key: key}} }

type KeyCaesar struct { 
	Shift int 
}

type Caesar struct { Cipher *CipherClassical[KeyCaesar] }
func (c *Caesar) GetText() []rune { return c.Cipher.Text }
func (c *Caesar) GetErrors() []error { return c.Cipher.Errors }
func (c *Caesar) Encrypt() { c.Cipher.Text = shiftCaesar(c.Cipher.Text, c.Cipher.Key.Shift) }
func (c *Caesar) Decrypt() { c.Cipher.Text = shiftCaesar(c.Cipher.Text, -c.Cipher.Key.Shift) }
func (c *Caesar) Verify() bool { return true }

func shiftCaesar(text []rune, shift int) []rune {
	shift = utils.Mod(shift, 26)

	for i, r := range text {
		if unicode.IsUpper(r) {
			text[i] = (r + rune(shift) - 'A') % 26 + 'A'
		} else if unicode.IsLower(r) {
			text[i] = (r + rune(shift) - 'a') % 26 + 'a'
		}
	}

	return text
}

func NewROT13(text []rune) *ROT13 { return &ROT13{Cipher: &CipherClassical[KeyNone]{Text: text, Key: &KeyNone{}}} }

type ROT13 struct { Cipher *CipherClassical[KeyNone] }
func (c *ROT13) GetText() []rune { return c.Cipher.Text }
func (c *ROT13) GetErrors() []error { return c.Cipher.Errors }
func (c *ROT13) Encrypt() { c.Cipher.Text = shiftCaesar(c.Cipher.Text, 13) }
func (c *ROT13) Decrypt() { c.Cipher.Text = shiftCaesar(c.Cipher.Text, 13) }
func (c *ROT13) Verify() bool { return true }

func NewKeyAffine(alphabet []rune, a int, b int) *KeyAffine { return &KeyAffine{Alphabet: alphabet, A: a, B: b} }
func NewAffine(text []rune, key *KeyAffine) *Affine { return &Affine{Cipher: &CipherClassical[KeyAffine]{Text: text, Key: key}} }

type KeyAffine struct {
	Alphabet []rune
	A int
	B int
}

type Affine struct { Cipher *CipherClassical[KeyAffine] }
func (c *Affine) GetText() []rune { return c.Cipher.Text }
func (c *Affine) GetErrors() []error { return c.Cipher.Errors }
func (c *Affine) Encrypt() { c.Cipher.Text = cryptAffine(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.A, c.Cipher.Key.B, true) }
func (c *Affine) Decrypt() { c.Cipher.Text = cryptAffine(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.A, c.Cipher.Key.B, false) }
func (c *Affine) Verify() bool { return true }

func cryptAffine(text []rune, alphabet []rune, a int, b int, encrypt bool) []rune {
	result := make([]rune, len(text))
	amap := buildIndexMap(alphabet)

	for i, r := range text {
		if encrypt {
			result[i] = alphabet[utils.Mod(a * amap[r] + b, len(alphabet))]
		} else {
			result[i] = alphabet[utils.Mod(utils.ModInverse(a, len(alphabet)) * (amap[r] - b), len(alphabet))]
		}
	}
	
	return result
}

func NewKeyAtbash(alphabet []rune) *KeyAtbash { return &KeyAtbash{Alphabet: alphabet} }
func NewAtbash(text []rune, key *KeyAtbash) *Atbash { return &Atbash{Cipher: &CipherClassical[KeyAtbash]{Text: text, Key: key}} }

type KeyAtbash struct {
	Alphabet []rune
}

type Atbash struct { Cipher *CipherClassical[KeyAtbash] }
func (c *Atbash) GetText() []rune { return c.Cipher.Text }
func (c *Atbash) GetErrors() []error { return c.Cipher.Errors }
func (c *Atbash) Encrypt() { c.Cipher.Text = cryptAffine(c.Cipher.Text, c.Cipher.Key.Alphabet, -1, -1, true) }
func (c *Atbash) Decrypt() { c.Cipher.Text = cryptAffine(c.Cipher.Text, c.Cipher.Key.Alphabet, -1, -1, true) }
func (c *Atbash) Verify() bool { return true }

func NewKeyPlayfair(alphabet []rune, null rune) *KeyPlayfair { return &KeyPlayfair{Alphabet: alphabet, Null: null} }
func NewPlayfair(text []rune, key *KeyPlayfair) *Playfair { return &Playfair{Cipher: &CipherClassical[KeyPlayfair]{Text: text, Key: key}} }

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

func cryptPlayfair(text []rune, alphabet []rune, null rune, encrypt bool) []rune {
	result := make([]rune, 0, len(text) + len(text) / 2 + 1)
	width := int(math.Sqrt(float64(len(alphabet))))
	amap := buildIndexMap(alphabet)
	inc, _ := utils.SwapIf(-1, 1, encrypt)

	for i := 0; i < len(text); i += 2 {
		i1 := amap[text[i]]
		var i2 int
		
		if i != len(text) - 1 && i1 != amap[text[i + 1]] {
			i2 = amap[text[i + 1]]
		} else {
			if i < len(text) - 2 {
				i--
			}
			
			if null == 0 {
				i2 = amap[alphabet[rand.Intn(len(alphabet))]]
			} else {
				i2 = amap[null]
			}
		}

		row1 := i1 / width
		col1 := i1 % width
		row2 := i2 / width
		col2 := i2 % width

		if row1 == row2 {
			result = append(result, alphabet[(col1 + inc + width) % width + row1 * width])
			result = append(result, alphabet[(col2 + inc + width) % width + row2 * width])
		} else if col1 == col2 {
			result = append(result, alphabet[col1 + (row1 + inc + width) % width * width])
			result = append(result, alphabet[col2 + (row2 + inc + width) % width * width])
		} else {
			result = append(result, alphabet[col2 + row1 * width])
			result = append(result, alphabet[col1 + row2 * width])
		}
	}

	return result
}
