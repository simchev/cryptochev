package classical

import (
	"unicode"
)

type KeySubstitute struct {
	Alphabet string
	SAlphabet string
}

type Substitute struct {
	Data *CipherClassicalData[KeySubstitute]
}

func (c *Substitute) GetText() string { return c.Data.Text }
func (c *Substitute) Encrypt() { c.Data.Text = substitute(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.SAlphabet) }
func (c *Substitute) Decrypt() { c.Data.Text = substitute(c.Data.Text, c.Data.Key.SAlphabet, c.Data.Key.Alphabet) }

func substitute(s string, alphabet string, salphabet string) string {
	rs := []rune(s)
	result := make([]rune, len(rs))
	rsa := []rune(salphabet)
	amap := buildIndexMap(alphabet)

	for i, r := range rs {
		result[i] = rsa[amap[r]]
	}

	return string(result)
}

type KeyShift int
type Shift struct {
	Data *CipherClassicalData[KeyShift]
}

func (c *Shift) GetText() string { return c.Data.Text }
func (c *Shift) Encrypt() { c.Data.Text = shift(c.Data.Text, int(*c.Data.Key)) }
func (c *Shift) Decrypt() { c.Data.Text = shift(c.Data.Text, -int(*c.Data.Key)) }

func shift(s string, shift int) string {
	shifted := []rune(s)
	rshift := rune(shift)

	for i, r := range s {
		shifted[i] = r + rshift
	}

	return string(shifted)
}

type KeyCaesar int
type Caesar struct {
	Data *CipherClassicalData[KeyCaesar]
}

func (c *Caesar) GetText() string { return c.Data.Text }
func (c *Caesar) Encrypt() { c.Data.Text = shiftAlphabet(c.Data.Text, int(*c.Data.Key)) }
func (c *Caesar) Decrypt() { c.Data.Text = shiftAlphabet(c.Data.Text, -int(*c.Data.Key)) }

func shiftAlphabet(s string, shift int) string {
	shifted := []rune(s)
	rshift := rune(shift % 26)
	if rshift < 0 {
		rshift += 26
	}

	for i, r := range shifted {
		if unicode.IsUpper(r) {
			shifted[i] = (shifted[i] + rshift - 'A') % 26 + 'A'
		} else if unicode.IsLower(r) {
			shifted[i] = (shifted[i] + rshift - 'a') % 26 + 'a'
		}
	}

	return string(shifted)
}

type KeyROT13 struct {}
type ROT13 struct {
	Data *CipherClassicalData[KeyROT13]
}

func (c *ROT13) GetText() string { return c.Data.Text }
func (c *ROT13) Encrypt() { c.Data.Text = shiftAlphabet(c.Data.Text, 13) }
func (c *ROT13) Decrypt() { c.Data.Text = shiftAlphabet(c.Data.Text, 13) }

type KeyVigenere struct {
	Alphabet string
	Key string
}

type Vigenere struct {
	Data *CipherClassicalData[KeyVigenere]
}

func (c *Vigenere) GetText() string { return c.Data.Text }
func (c *Vigenere) Encrypt() { c.Data.Text = cryptVigenere(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Key, true) }
func (c *Vigenere) Decrypt() { c.Data.Text = cryptVigenere(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Key, false) }

func cryptVigenere(s string, alphabet string, key string, encrypt bool) string {
	if key == "" {
		key = alphabet
	}

	rs := []rune(s)
	result := make([]rune, len(rs))
	amap := buildIndexMap(alphabet)
	ra := []rune(alphabet)
	rk := []rune(key)
	
	for i, r := range rs {
		if encrypt {
			result[i] = ra[(amap[r] + amap[rk[i % len(rk)]]) % len(ra)]
		} else {
			result[i] = ra[(amap[r] - amap[rk[i % len(rk)]] + len(ra)) % len(ra)]
		}
	}

	return string(result)
}

type VigenereBeaufort struct {
	Data *CipherClassicalData[KeyVigenere]
}

func (c *VigenereBeaufort) GetText() string { return c.Data.Text }
func (c *VigenereBeaufort) Encrypt() { c.Data.Text = cryptVigenere(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Key, false) }
func (c *VigenereBeaufort) Decrypt() { c.Data.Text = cryptVigenere(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Key, true) }

func gronsfeldToVigenereKey(alphabet string, key string) string {
	ra := []rune(alphabet)
	rkey := []rune(key)
	keyv := make([]rune, 0, len(rkey))

	for _, r := range rkey {
		if unicode.IsDigit(r) {
			keyv = append(keyv, ra[r - '0'])
		}
	}

	return string(keyv)
}

type VigenereGronsfeld struct {
	Data *CipherClassicalData[KeyVigenere]
}

func (c *VigenereGronsfeld) GetText() string { return c.Data.Text }
func (c *VigenereGronsfeld) Encrypt() { c.Data.Text = cryptVigenere(c.Data.Text, c.Data.Key.Alphabet, gronsfeldToVigenereKey(c.Data.Key.Alphabet, c.Data.Key.Key), true) }
func (c *VigenereGronsfeld) Decrypt() { c.Data.Text = cryptVigenere(c.Data.Text, c.Data.Key.Alphabet, gronsfeldToVigenereKey(c.Data.Key.Alphabet, c.Data.Key.Key), false) }

