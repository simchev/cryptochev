package classical

import (
	"cryptochev/utils"
	"math"
	"math/rand"
)

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