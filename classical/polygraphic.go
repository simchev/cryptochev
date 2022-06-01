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

			for i2 == i1 {
				i2 = amap[alphabet[rand.Intn(len(alphabet))]]
			}
		}

		row1, col1 := i1 / width, i1 % width
		row2, col2 := i2 / width, i2 % width

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

func NewKeyTwoSquareV(alphabet1, alphabet2 []rune, transparent bool) *KeyTwoSquareV { 
	return &KeyTwoSquareV{Alphabet1: alphabet1, Alphabet2: alphabet2, Transparent: transparent} 
}
func NewTwoSquareV(text []rune, key *KeyTwoSquareV) *TwoSquareV { return &TwoSquareV{Cipher: &CipherClassical[KeyTwoSquareV]{Text: text, Key: key}} }

type KeyTwoSquareV struct {
	Alphabet1 []rune
	Alphabet2 []rune
	Transparent bool
}

type TwoSquareV struct { Cipher *CipherClassical[KeyTwoSquareV] }
func (c *TwoSquareV) GetText() []rune { return c.Cipher.Text }
func (c *TwoSquareV) GetErrors() []error { return c.Cipher.Errors }
func (c *TwoSquareV) Encrypt() { 
	c.Cipher.Text = cryptTwoSquareV(c.Cipher.Text, c.Cipher.Key.Alphabet1, c.Cipher.Key.Alphabet2, c.Cipher.Key.Transparent, true) 
}
func (c *TwoSquareV) Decrypt() { 
	c.Cipher.Text = cryptTwoSquareV(c.Cipher.Text, c.Cipher.Key.Alphabet1, c.Cipher.Key.Alphabet2, c.Cipher.Key.Transparent, false) 
}
func (c *TwoSquareV) Verify() bool { return true }

func cryptTwoSquareV(text, alphabet1, alphabet2 []rune, transparent, encrypt bool) []rune {
	result := make([]rune, len(text))
	width := int(math.Sqrt(float64(len(alphabet1))))
	amap1 := buildIndexMap(alphabet1)
	amap2 := buildIndexMap(alphabet2)
	inc, _ := utils.SwapIf(-1, 1, encrypt)

	for i := 0; i < len(text); i += 2 {
		i1 := amap1[text[i]]
		i2 := amap2[text[i + 1]]
		row1, col1 := i1 / width, i1 % width
		row2, col2 := i2 / width, i2 % width

		if col1 == col2 {
			if transparent {
				result[i] = alphabet1[col1 + row1 * width]
				result[i + 1] = alphabet2[col2 + row2 * width]
			} else {
				result[i] = alphabet1[col1 + (row1 + inc + width) % width * width]
				result[i + 1] = alphabet2[col2 + (row2 + inc + width) % width * width]
			}
		} else {
			result[i] = alphabet1[col2 + row1 * width]
			result[i + 1] = alphabet2[col1 + row2 * width]
		}
	}

	return result
}

func NewKeyTwoSquareH(alphabet1, alphabet2 []rune, transparent bool) *KeyTwoSquareH { 
	return &KeyTwoSquareH{Alphabet1: alphabet1, Alphabet2: alphabet2, Transparent: transparent} 
}
func NewTwoSquareH(text []rune, key *KeyTwoSquareH) *TwoSquareH { return &TwoSquareH{Cipher: &CipherClassical[KeyTwoSquareH]{Text: text, Key: key}} }

type KeyTwoSquareH struct {
	Alphabet1 []rune
	Alphabet2 []rune
	Transparent bool
}

type TwoSquareH struct { Cipher *CipherClassical[KeyTwoSquareH] }
func (c *TwoSquareH) GetText() []rune { return c.Cipher.Text }
func (c *TwoSquareH) GetErrors() []error { return c.Cipher.Errors }
func (c *TwoSquareH) Encrypt() { 
	c.Cipher.Text = encryptTwoSquareH(c.Cipher.Text, c.Cipher.Key.Alphabet1, c.Cipher.Key.Alphabet2, c.Cipher.Key.Transparent) 
}
func (c *TwoSquareH) Decrypt() { 
	c.Cipher.Text = decryptTwoSquareH(c.Cipher.Text, c.Cipher.Key.Alphabet1, c.Cipher.Key.Alphabet2, c.Cipher.Key.Transparent) 
}
func (c *TwoSquareH) Verify() bool { return true }

func encryptTwoSquareH(text, alphabet1, alphabet2 []rune, transparent bool) []rune {
	result := make([]rune, len(text))
	width := int(math.Sqrt(float64(len(alphabet1))))
	amap1 := buildIndexMap(alphabet1)
	amap2 := buildIndexMap(alphabet2)

	for i := 0; i < len(text); i += 2 {
		i1 := amap1[text[i]]
		i2 := amap2[text[i + 1]]
		row1, col1 := i1 / width, i1 % width
		row2, col2 := i2 / width, i2 % width

		if row1 == row2 {
			if transparent {
				result[i] = alphabet2[col2 + row2 * width]
				result[i + 1] = alphabet1[col1 + row1 * width]
			} else {
				result[i] = alphabet2[(col2 + 1 + width) % width + row2 * width]
				result[i + 1] = alphabet1[(col1 + 1 + width) % width + row1 * width]
			}
		} else {
			result[i] = alphabet2[col2 + row1 * width]
			result[i + 1] = alphabet1[col1 + row2 * width]
		}
	}

	return result
}

func decryptTwoSquareH(text, alphabet1, alphabet2 []rune, transparent bool) []rune {
	result := make([]rune, len(text))
	width := int(math.Sqrt(float64(len(alphabet1))))
	amap1 := buildIndexMap(alphabet1)
	amap2 := buildIndexMap(alphabet2)

	for i := 0; i < len(text); i += 2 {
		i1 := amap2[text[i]]
		i2 := amap1[text[i + 1]]
		row1, col1 := i1 / width, i1 % width
		row2, col2 := i2 / width, i2 % width

		if row1 == row2 {
			if transparent {
				result[i] = alphabet1[col2 + row2 * width]
				result[i + 1] = alphabet2[col1 + row1 * width]
			} else {
				result[i] = alphabet1[(col2 - 1 + width) % width + row2 * width]
				result[i + 1] = alphabet2[(col1 - 1 + width) % width + row1 * width]
			}
		} else {
			result[i] = alphabet1[col2 + row1 * width]
			result[i + 1] = alphabet2[col1 + row2 * width]
		}
	}

	return result
}

func NewKeyFourSquare(a1, a2, a3, a4 []rune) *KeyFourSquare { 
	return &KeyFourSquare{Alphabet1: a1, Alphabet2: a2, Alphabet3: a3, Alphabet4: a4}
}
func NewFourSquare(text []rune, key *KeyFourSquare) *FourSquare { return &FourSquare{Cipher: &CipherClassical[KeyFourSquare]{Text: text, Key: key}} }

type KeyFourSquare struct {
	Alphabet1 []rune
	Alphabet2 []rune
	Alphabet3 []rune
	Alphabet4 []rune
}

type FourSquare struct { Cipher *CipherClassical[KeyFourSquare] }
func (c *FourSquare) GetText() []rune { return c.Cipher.Text }
func (c *FourSquare) GetErrors() []error { return c.Cipher.Errors }
func (c *FourSquare) Encrypt() { 
	c.Cipher.Text = encryptFourSquare(c.Cipher.Text, c.Cipher.Key.Alphabet1, c.Cipher.Key.Alphabet2, 
									  c.Cipher.Key.Alphabet3, c.Cipher.Key.Alphabet4)
}
func (c *FourSquare) Decrypt() { 
	c.Cipher.Text = decryptFourSquare(c.Cipher.Text, c.Cipher.Key.Alphabet1, c.Cipher.Key.Alphabet2, 
									  c.Cipher.Key.Alphabet3, c.Cipher.Key.Alphabet4)
}
func (c *FourSquare) Verify() bool { return true }

func encryptFourSquare(text, a1, a2, a3, a4 []rune) []rune {
	result := make([]rune, len(text))
	width := int(math.Sqrt(float64(len(a1))))
	amap1 := buildIndexMap(a1)
	amap4 := buildIndexMap(a4)

	for i := 0; i < len(text); i += 2 {
		i1 := amap1[text[i]]
		i2 := amap4[text[i + 1]]
		row1, col1 := i1 / width, i1 % width
		row2, col2 := i2 / width, i2 % width
		result[i] = a2[col2 + row1 * width]
		result[i + 1] = a3[col1 + row2 * width]
	}

	return result
}

func decryptFourSquare(text, a1, a2, a3, a4 []rune) []rune {
	result := make([]rune, len(text))
	width := int(math.Sqrt(float64(len(a1))))
	amap2 := buildIndexMap(a2)
	amap3 := buildIndexMap(a3)

	for i := 0; i < len(text); i += 2 {
		i1 := amap2[text[i]]
		i2 := amap3[text[i + 1]]
		row1, col1 := i1 / width, i1 % width
		row2, col2 := i2 / width, i2 % width
		result[i] = a1[col2 + row1 * width]
		result[i + 1] = a4[col1 + row2 * width]
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
