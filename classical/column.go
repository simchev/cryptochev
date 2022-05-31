package classical

import (
	"cryptochev/utils"
	"math"
	"sort"
)

func getSortedKeyIndices(key []rune) []int {
	keyIndices := make([]int, len(key))
	for i := 0; i < len(key); i++ {
		keyIndices[i] = i;
	}

	sort.SliceStable(keyIndices, func(i, j int) bool {
		return key[keyIndices[i]] < key[keyIndices[j]]
	})

	return keyIndices
}

func getSortedKeyPositions(key []rune) []int {
	rKeyPositions := make([]int, len(key))
	rKeyIndices := make([]int, len(key))
	for i := 0; i < len(key); i++ {
		rKeyIndices[i] = i;
	}

	sort.SliceStable(rKeyIndices, func(i, j int) bool {
		return key[rKeyIndices[i]] < key[rKeyIndices[j]]
	})

	for i := range rKeyPositions {
		for j := range rKeyIndices {
			if rKeyIndices[j] == i {
				rKeyPositions[i] = j
				break
			}
		}
	}

	return rKeyPositions
}

func NewKeyColumn(key []rune) *KeyColumn { return &KeyColumn{Key: key} }
func NewColumn(text []rune, key *KeyColumn) *Column { return &Column{Cipher: &CipherClassical[KeyColumn]{Text: text, Key: key}} }

type KeyColumn struct { 
	Key []rune
}

type Column struct { Cipher *CipherClassical[KeyColumn] }
func (c *Column) GetText() []rune { return c.Cipher.Text }
func (c *Column) GetErrors() []error { return c.Cipher.Errors }
func (c *Column) Encrypt() { c.Cipher.Text = cryptColumn(c.Cipher.Text, c.Cipher.Key.Key, true) }
func (c *Column) Decrypt() { c.Cipher.Text = cryptColumn(c.Cipher.Text, c.Cipher.Key.Key, false) }
func (c *Column) Verify() bool { return true }

func cryptColumn(text, key []rune, encrypt bool) []rune {
	result := make([]rune, len(text))
	rKeyIndices := getSortedKeyIndices(key)

	rows := int(math.Ceil(float64(len(text)) / float64(len(key))))
	sIndex := 0
	for _, i := range rKeyIndices {
		for j := 0; j < rows; j++ {
			index := i + j * len(key)
			if index < len(text) {
				i1, i2 := utils.SwapIf(index, sIndex, encrypt)
				result[i1] = text[i2]
				sIndex++
			}
		}
	}

	return result
}

func NewKeyMyszkowski(key []rune) *KeyMyszkowski { return &KeyMyszkowski{Key: key} }
func NewMyszkowski(text []rune, key *KeyMyszkowski) *Myszkowski { return &Myszkowski{Cipher: &CipherClassical[KeyMyszkowski]{Text: text, Key: key}} }

type KeyMyszkowski struct {
	Key []rune 
}

type Myszkowski struct { Cipher *CipherClassical[KeyMyszkowski] }
func (c *Myszkowski) GetText() []rune { return c.Cipher.Text }
func (c *Myszkowski) GetErrors() []error { return c.Cipher.Errors }
func (c *Myszkowski) Encrypt() { c.Cipher.Text = cryptMyszkowski(c.Cipher.Text, c.Cipher.Key.Key, true) }
func (c *Myszkowski) Decrypt() { c.Cipher.Text = cryptMyszkowski(c.Cipher.Text, c.Cipher.Key.Key, false) }
func (c *Myszkowski) Verify() bool { return true }

func cryptMyszkowski(text, key []rune, encrypt bool) []rune {
	result := make([]rune, len(text))
	keyIndices := getSortedKeyIndices(key)

	rows := int(math.Ceil(float64(len(text)) / float64(len(key))))
	sIndex := 0
	for i := 0; i < len(keyIndices); i++ { 
		equivalent := 0
		for j := 1; i + j < len(keyIndices); j++ {
			if key[keyIndices[i + j]] == key[keyIndices[i]] {
				equivalent++
			} else {
				break
			}
		} 

		for j := 0; j < rows; j++ {
			for k := 0; k < equivalent + 1; k++ {
				index := keyIndices[i + k] + j * len(key)
				if index < len(text) {
					i1, i2 := utils.SwapIf(index, sIndex, encrypt)
					result[i1] = text[i2]
					sIndex++
				}
			}
		}

		i += equivalent
	}

	return result
}

func NewKeyColumnDCount(key, dkey []rune) *KeyColumnDCount { return &KeyColumnDCount{Key: key, DKey: dkey} }
func NewColumnDCount(text []rune, key *KeyColumnDCount) *ColumnDCount { return &ColumnDCount{Cipher: &CipherClassical[KeyColumnDCount]{Text: text, Key: key}} }

type KeyColumnDCount struct {
	Key []rune
	DKey []rune
}

type ColumnDCount struct { Cipher *CipherClassical[KeyColumnDCount] }
func (c *ColumnDCount) GetText() []rune { return c.Cipher.Text }
func (c *ColumnDCount) GetErrors() []error { return c.Cipher.Errors }
func (c *ColumnDCount) Encrypt() { c.Cipher.Text = encryptColumnDCount(c.Cipher.Text, c.Cipher.Key.Key, c.Cipher.Key.DKey) }
func (c *ColumnDCount) Decrypt() { c.Cipher.Text = decryptColumnDCount(c.Cipher.Text, c.Cipher.Key.Key, c.Cipher.Key.DKey) }
func (c *ColumnDCount) Verify() bool { return true }

func encryptColumnDCount(text, key, dkey []rune) []rune {
	if len(dkey) < 2 {
		return text
	}

	result := make([]rune, 0, len(text))
	keyIndices := getSortedKeyIndices(key)
	keyPositions := getSortedKeyPositions(dkey)
	gaps := 0
	gapPos := 0

	for gapPos < len(text) + gaps {
		for _, p := range keyPositions {
			gapPos += p
			if gapPos < len(text) + gaps {
				gaps++
				gapPos++
			} else {
				break
			}
		}
	}

	rows := int(math.Ceil(float64(len(text) + gaps) / float64(len(key))))
	gapCount := 0
	posIndex := 0
	nextGap := keyPositions[0]
	grid := make([][]rune, rows)
	for i := range grid {
		grid[i] = make([]rune, len(key))
	}

	for i := 0; i < rows; i++ {
		for j := 0; j < len(key); j++ {
			index := j + i * len(key)
			if index == nextGap {
				posIndex++
				if posIndex >= len(keyPositions) {
					posIndex = 0
				}
				nextGap += keyPositions[posIndex] + 1
				gapCount++
			} else if index - gapCount < len(text) {
				grid[i][j] = text[index - gapCount]
			} else {
				break
			}
		}
	}

	for _, i := range keyIndices {
		for j := 0; j < rows; j++ {
			if grid[j][i] != 0 {
				result = append(result, grid[j][i])
			}
		}
	}

	return result
}

func decryptColumnDCount(text, key, dkey []rune) []rune {
	if len(dkey) < 2 {
		return text
	}

	result := make([]rune, 0, len(text))
	keyIndices := getSortedKeyIndices(key)
	keyPositions := getSortedKeyPositions(dkey)
	gaps := 0
	gapPos := 0
	gapIndices := make([]int, 0, int(math.Ceil(float64(utils.TriangleNumber(len(key))) / float64(utils.TriangleNumber(len(key) - 1)) * float64(len(text)))))

	for gapPos < len(text) + gaps {
		for _, p := range keyPositions {
			gapPos += p
			if gapPos < len(text) + gaps {
				gapIndices = append(gapIndices, gapPos)
				gaps++
				gapPos++
			} else {
				break
			}
		}
	}

	rows := int(math.Ceil(float64(len(text) + gaps) / float64(len(key))))
	sIndex := 0
	grid := make([][]rune, rows)
	for i := range grid {
		grid[i] = make([]rune, len(key))
	}

	for _, i := range keyIndices {
		for j := 0; j < rows; j++ {
			index := i + j * len(key)
			if !utils.Contains(gapIndices, index) && index < len(text) + gaps && sIndex < len(text) {
				grid[j][i] = text[sIndex]
				sIndex++
			}
		}
	}

	for i := 0; i < rows; i++ {
		for j := 0; j < len(key); j++ {
			if grid[i][j] != 0 {
				result = append(result, grid[i][j])
			}
		}
	}

	return result
}

func NewKeyColumnDLine(key []rune, fill bool) *KeyColumnDLine { return &KeyColumnDLine{Key: key, Fill: fill} }
func NewColumnDLine(text []rune, key *KeyColumnDLine) *ColumnDLine { return &ColumnDLine{Cipher: &CipherClassical[KeyColumnDLine]{Text: text, Key: key}} }

type KeyColumnDLine struct {
	Key []rune
	Fill bool
}

type ColumnDLine struct { Cipher *CipherClassical[KeyColumnDLine] }
func (c *ColumnDLine) GetText() []rune { return c.Cipher.Text }
func (c *ColumnDLine) GetErrors() []error { return c.Cipher.Errors }
func (c *ColumnDLine) Encrypt() { c.Cipher.Text = encryptColumnDLine(c.Cipher.Text, c.Cipher.Key.Key, c.Cipher.Key.Fill) }
func (c *ColumnDLine) Decrypt() { c.Cipher.Text = decryptColumnDLine(c.Cipher.Text, c.Cipher.Key.Key, c.Cipher.Key.Fill) }
func (c *ColumnDLine) Verify() bool { return true }

func buildDLineGrid(text []rune, keyIndices []int, keySize int, fill bool) ([][]rune, int) {
	block := 0
	if fill {
		block = keySize * keySize
	} else {
		block = utils.TriangleNumber(keySize)
	}
	blocks := int(math.Ceil(float64(len(text)) / float64(block)))
	rows := blocks * keySize

	grid := make([][]rune, rows)
	for i := range grid {
		grid[i] = make([]rune, keySize)
	}
	
	sIndex := 0
	blockIndex := 0
	out: for sIndex < len(text) {
		blockPos := blockIndex * keySize
		for i, ki := range keyIndices {
			for j := 0; j < keySize; j++ {
				grid[i + blockPos][j] = text[sIndex]
				sIndex++

				if sIndex >= len(text) {
					break out
				} else if j == ki {
					break
				}
			}
		}

		if fill {
			for i := blockPos; i < keySize + blockPos; i++ {
				for j := 0; j < keySize; j++ {
					if grid[i][j] == 0 {
						grid[i][j] = text[sIndex]
						sIndex++

						if sIndex >= len(text) {
							break out
						}
					}
				}
			}
		}

		blockIndex++
	}

	return grid, rows
}

func encryptColumnDLine(text, key []rune, fill bool) []rune {
	if len(key) < 2 {
		return text
	}
	
	result := make([]rune, 0, len(text))
	keyIndices := getSortedKeyIndices(key)
	grid, rows := buildDLineGrid(text, keyIndices, len(key), fill)

	for _, i := range keyIndices {
		for j := 0; j < rows; j++ {
			if grid[j][i] != 0 {
				result = append(result, grid[j][i])
			}
		}
	}

	return result
}

func decryptColumnDLine(text, key []rune, fill bool) []rune {
	if len(key) < 2 {
		return text
	}

	result := make([]rune, 0, len(text))
	keyIndices := getSortedKeyIndices(key)
	grid, rows := buildDLineGrid(text, keyIndices, len(key), fill)

	grid2 := make([][]rune, rows)
	for i := range grid2 {
		grid2[i] = make([]rune, len(key))
	}

	sIndex := 0
	for _, i := range keyIndices {
		for j := 0; j < rows; j++ {
			if grid[j][i] != 0 {
				grid2[j][i] = text[sIndex]
				sIndex++
			}
		}
	}

	sIndex = 0
	blockIndex := 0
	out: for sIndex < len(text) {
		blockPos := blockIndex * len(key)
		for i, ki := range keyIndices {
			for j := 0; j < len(key); j++ {
				result = append(result, grid2[i + blockPos][j])
				sIndex++

				if sIndex >= len(text) {
					break out
				} else if j == ki {
					break
				}
			}
		}

		if fill {
			for i, ki := range keyIndices {
				for j := 0; j < len(key); j++ {
					if grid2[i + blockPos][j] != 0 && j > ki {
						result = append(result, grid2[i + blockPos][j])
						sIndex++

						if sIndex >= len(text) {
							break out
						}
					}
				}
			}
		}

		blockIndex++
	}

	return result
}
