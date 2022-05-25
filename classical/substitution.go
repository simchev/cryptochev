package classical

import (
	"unicode"
)

type KeyShift int
type Shift struct {
	Data *CipherClassicalData[KeyShift]
}

func (c *Shift) GetText() string { return c.Data.Text }
func (c *Shift) Encrypt() { c.Data.Text = shift(c.Data.Text, int(*c.Data.Key)) }
func (c *Shift) Decrypt() { c.Data.Text = shift(c.Data.Text, -int(*c.Data.Key)) }

func shift(s string, shift int) string {
	shifted := make([]rune, len(s))
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

	for i, r := range s {
		if unicode.IsUpper(r) {
			shifted[i] = r + rshift

			if shifted[i] < 65 {
				shifted[i] += 26
			} else if shifted[i] > 90 {
				shifted[i] -= 26
			}
		} else if unicode.IsLower(r) {
			shifted[i] = r + rshift

			if shifted[i] < 97 {
				shifted[i] += 26
			} else if shifted[i] > 122 {
				shifted[i] -= 26
			}
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

	result := make([]rune, len(s))
	amap := buildIndexMap(alphabet)
	ra := []rune(alphabet)
	rk := []rune(key)
	
	for i, r := range s {
		if encrypt {
			result[i] = ra[(amap[r] + amap[rk[i % len(rk)]]) % len(alphabet)]
		} else {
			result[i] = ra[(amap[r] - amap[rk[i % len(rk)]] + len(alphabet)) % len(alphabet)]
		}
	}

	return string(result)
}
