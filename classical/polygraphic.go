package classical

import (
	"cryptochev/utils"
	"math"
	"math/rand"

	"gonum.org/v1/gonum/mat"
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

func cryptPlayfair(text, alphabet []rune, null rune, encrypt bool) []rune {
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

func NewKeyHill(alphabet []rune, m *mat.Dense) *KeyHill { return &KeyHill{Alphabet: alphabet, Matrix: m} }
func NewHill(text []rune, key *KeyHill) *Hill { return &Hill{Cipher: &CipherClassical[KeyHill]{Text: text, Key: key}} }

type KeyHill struct {
	Alphabet []rune
	Matrix *mat.Dense
}

type Hill struct { Cipher *CipherClassical[KeyHill] }
func (c *Hill) GetText() []rune { return c.Cipher.Text }
func (c *Hill) GetErrors() []error { return c.Cipher.Errors }
func (c *Hill) Encrypt() { c.Cipher.Text = cryptHill(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Matrix, true) }
func (c *Hill) Decrypt() { c.Cipher.Text = cryptHill(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Matrix, false) }
func (c *Hill) Verify() bool { return true }

func cryptHill(text, alphabet []rune, m *mat.Dense, encrypt bool) []rune {
	r, _ := m.Dims()
	text = ToPadded(text, r)
	result := make([]rune, len(text))
	amap := buildIndexMap(alphabet)
	col := make([]float64, r)

	if !encrypt {
		utils.ModInverseMatrix(m, len(alphabet))
	}

	for i := 0; i < len(text); i += r {
		for j := range col {
			col[j] = float64(amap[text[i + j]])
		}

		var mres mat.Dense
		mres.Mul(m, mat.NewDense(r, 1, col))
		for j := range col {
			result[i + j] = alphabet[utils.Mod(int(mres.At(j, 0)), len(alphabet))]
		}
	}

	return result
}
