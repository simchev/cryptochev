package classical

import (
	"cryptochev/utils"
	"unicode"
)

func NewKeySubstitute(alphabet, salphabet []rune) *KeySubstitute { return &KeySubstitute{Alphabet: alphabet, SAlphabet: salphabet} }
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

func substitute(text, alphabet, salphabet []rune) []rune {
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

func NewKeyShiftAlphabet(alphabet []rune, shift int) *KeyShiftAlphabet { return &KeyShiftAlphabet{Alphabet: alphabet, Shift: shift} }
func NewShiftAlphabet(text []rune, key *KeyShiftAlphabet) *ShiftAlphabet { return &ShiftAlphabet{Cipher: &CipherClassical[KeyShiftAlphabet]{Text: text, Key: key}} }

type KeyShiftAlphabet struct { 
	Alphabet []rune
	Shift int 
}

type ShiftAlphabet struct { Cipher *CipherClassical[KeyShiftAlphabet] }
func (c *ShiftAlphabet) GetText() []rune { return c.Cipher.Text }
func (c *ShiftAlphabet) GetErrors() []error { return c.Cipher.Errors }
func (c *ShiftAlphabet) Encrypt() { c.Cipher.Text = shiftAlphabet(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Shift) }
func (c *ShiftAlphabet) Decrypt() { c.Cipher.Text = shiftAlphabet(c.Cipher.Text, c.Cipher.Key.Alphabet, -c.Cipher.Key.Shift) }
func (c *ShiftAlphabet) Verify() bool { return true }

func shiftAlphabet(text, alphabet []rune, shift int) []rune {
	result := make([]rune, len(text))
	amap := buildIndexMap(alphabet)

	for i, r := range text {
		result[i] = alphabet[utils.Mod(amap[r] + shift, len(alphabet))]
	}

	return result
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

func NewKeyAffine(alphabet []rune, a, b int) *KeyAffine { return &KeyAffine{Alphabet: alphabet, A: a, B: b} }
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

func cryptAffine(text, alphabet []rune, a, b int, encrypt bool) []rune {
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

func NewKeyChaocipher(left, right []rune) *KeyChaocipher { return &KeyChaocipher{Left: left, Right: right} }
func NewChaocipher(text []rune, key *KeyChaocipher) *Chaocipher { return &Chaocipher{Cipher: &CipherClassical[KeyChaocipher]{Text: text, Key: key}} }

type KeyChaocipher struct { 
	Left []rune
	Right []rune
}

type Chaocipher struct { Cipher *CipherClassical[KeyChaocipher] }
func (c *Chaocipher) GetText() []rune { return c.Cipher.Text }
func (c *Chaocipher) GetErrors() []error { return c.Cipher.Errors }
func (c *Chaocipher) Encrypt() { c.Cipher.Text = cryptChaocipher(c.Cipher.Text, c.Cipher.Key.Left, c.Cipher.Key.Right, true) }
func (c *Chaocipher) Decrypt() { c.Cipher.Text = cryptChaocipher(c.Cipher.Text, c.Cipher.Key.Left, c.Cipher.Key.Right, false) }
func (c *Chaocipher) Verify() bool { return true }

func cryptChaocipher(text, left, right []rune, encrypt bool) []rune {
	result := make([]rune, len(text))
	nadir := len(left) / 2
	var temp rune

	for i, r := range text {
		var index int

		if encrypt {
			index = utils.IndexOf(right, r)
			result[i] = left[index]
		} else {
			index = utils.IndexOf(left, r)
			result[i] = right[index]
		}

		left = shiftAlphabet(left, left, index)
		temp = left[1]
		for j := 2; j <= nadir; j++ {
			left[j - 1] = left[j]
		}
		left[nadir] = temp

		right = shiftAlphabet(right, right, index + 1)
		temp = right[2]
		for j := 3; j <= nadir; j++ {
			right[j - 1] = right[j]
		}
		right[nadir] = temp
	}

	return result
}
