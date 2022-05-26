package classical

import (
	"cryptochev/utils"
	"math"
	"sort"
)

type KeyColumn []rune
type Column struct {
	Data *CipherClassicalData[KeyColumn]
}

func (c *Column) GetText() []rune { return c.Data.Text }
func (c *Column) Encrypt() { c.Data.Text = cryptColumn(c.Data.Text, []rune(*c.Data.Key), true) }
func (c *Column) Decrypt() { c.Data.Text = cryptColumn(c.Data.Text, []rune(*c.Data.Key), false) }

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

func cryptColumn(s []rune, key []rune, encrypt bool) []rune {
	result := make([]rune, len(s))
	rKeyIndices := getSortedKeyIndices(key)

	rows := int(math.Ceil(float64(len(s)) / float64(len(key))))
	sIndex := 0
	for _, i := range rKeyIndices {
		for j := 0; j < rows; j++ {
			index := i + j * len(key)
			if index < len(s) {
				i1, i2 := utils.ReverseIf(index, sIndex, encrypt)
				result[i1] = s[i2]
				sIndex++
			}
		}
	}

	return result
}

type KeyMyszkowski []rune
type Myszkowski struct {
	Data *CipherClassicalData[KeyMyszkowski]
}

func (c *Myszkowski) GetText() []rune { return c.Data.Text }
func (c *Myszkowski) Encrypt() { c.Data.Text = cryptMyszkowski(c.Data.Text, []rune(*c.Data.Key), true) }
func (c *Myszkowski) Decrypt() { c.Data.Text = cryptMyszkowski(c.Data.Text, []rune(*c.Data.Key), false) }

func cryptMyszkowski(s []rune, key []rune, encrypt bool) []rune {
	result := make([]rune, len(s))
	keyIndices := getSortedKeyIndices(key)

	rows := int(math.Ceil(float64(len(s)) / float64(len(key))))
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
				if index < len(s) {
					i1, i2 := utils.ReverseIf(index, sIndex, encrypt)
					result[i1] = s[i2]
					sIndex++
				}
			}
		}

		i += equivalent
	}

	return result
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

type KeyColumnDCount struct {
	CKey []rune
	DKey []rune
}

type ColumnDCount struct {
	Data *CipherClassicalData[KeyColumnDCount]
}

func (c *ColumnDCount) GetText() []rune { return c.Data.Text }
func (c *ColumnDCount) Encrypt() { c.Data.Text = encryptColumnDCount(c.Data.Text, c.Data.Key.CKey, c.Data.Key.DKey) }
func (c *ColumnDCount) Decrypt() { c.Data.Text = decryptColumnDCount(c.Data.Text, c.Data.Key.CKey, c.Data.Key.DKey) }

func encryptColumnDCount(s []rune, key []rune, dkey []rune) []rune {
	if len(dkey) < 2 {
		return s
	}

	result := make([]rune, 0, len(s))
	keyIndices := getSortedKeyIndices(key)
	keyPositions := getSortedKeyPositions(dkey)
	gaps := 0
	gapPos := 0

	for gapPos < len(s) + gaps {
		for _, p := range keyPositions {
			gapPos += p
			if gapPos < len(s) + gaps {
				gaps++
				gapPos++
			} else {
				break
			}
		}
	}

	rows := int(math.Ceil(float64(len(s) + gaps) / float64(len(key))))
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
			} else if index - gapCount < len(s) {
				grid[i][j] = s[index - gapCount]
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

func decryptColumnDCount(s []rune, key []rune, dkey []rune) []rune {
	if len(dkey) < 2 {
		return s
	}

	result := make([]rune, 0, len(s))
	keyIndices := getSortedKeyIndices(key)
	keyPositions := getSortedKeyPositions(dkey)
	gaps := 0
	gapPos := 0
	gapIndices := make([]int, 0, int(math.Ceil(float64(triangleNumber(len(key))) / float64(triangleNumber(len(key) - 1)) * float64(len(s)))))

	for gapPos < len(s) + gaps {
		for _, p := range keyPositions {
			gapPos += p
			if gapPos < len(s) + gaps {
				gapIndices = append(gapIndices, gapPos)
				gaps++
				gapPos++
			} else {
				break
			}
		}
	}

	rows := int(math.Ceil(float64(len(s) + gaps) / float64(len(key))))
	sIndex := 0
	grid := make([][]rune, rows)
	for i := range grid {
		grid[i] = make([]rune, len(key))
	}

	for _, i := range keyIndices {
		for j := 0; j < rows; j++ {
			index := i + j * len(key)
			if !utils.Contains(gapIndices, index) && index < len(s) + gaps && sIndex < len(s) {
				grid[j][i] = s[sIndex]
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

type KeyColumnDLine struct {
	Key []rune
	Fill bool
}

type ColumnDLine struct {
	Data *CipherClassicalData[KeyColumnDLine]
}

func (c *ColumnDLine) GetText() []rune { return c.Data.Text }
func (c *ColumnDLine) Encrypt() { c.Data.Text = encryptColumnDLine(c.Data.Text, c.Data.Key.Key, c.Data.Key.Fill) }
func (c *ColumnDLine) Decrypt() { c.Data.Text = decryptColumnDLine(c.Data.Text, c.Data.Key.Key, c.Data.Key.Fill) }

func buildDLineGrid(s []rune, keyIndices []int, keySize int, fill bool) ([][]rune, int) {
	block := 0
	if fill {
		block = keySize * keySize
	} else {
		block = triangleNumber(keySize)
	}
	blocks := int(math.Ceil(float64(len(s)) / float64(block)))
	rows := blocks * keySize

	grid := make([][]rune, rows)
	for i := range grid {
		grid[i] = make([]rune, keySize)
	}
	
	sIndex := 0
	blockIndex := 0
	out: for sIndex < len(s) {
		blockPos := blockIndex * keySize
		for i, ki := range keyIndices {
			for j := 0; j < keySize; j++ {
				grid[i + blockPos][j] = s[sIndex]
				sIndex++

				if sIndex >= len(s) {
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
						grid[i][j] = s[sIndex]
						sIndex++

						if sIndex >= len(s) {
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

func encryptColumnDLine(s []rune, key []rune, fill bool) []rune {
	if len(key) < 2 {
		return s
	}
	
	result := make([]rune, 0, len(s))
	keyIndices := getSortedKeyIndices(key)
	grid, rows := buildDLineGrid(s, keyIndices, len(key), fill)

	for _, i := range keyIndices {
		for j := 0; j < rows; j++ {
			if grid[j][i] != 0 {
				result = append(result, grid[j][i])
			}
		}
	}

	return result
}

func decryptColumnDLine(s []rune, key []rune, fill bool) []rune {
	if len(key) < 2 {
		return s
	}

	result := make([]rune, 0, len(s))
	keyIndices := getSortedKeyIndices(key)
	grid, rows := buildDLineGrid(s, keyIndices, len(key), fill)

	grid2 := make([][]rune, rows)
	for i := range grid2 {
		grid2[i] = make([]rune, len(key))
	}

	sIndex := 0
	for _, i := range keyIndices {
		for j := 0; j < rows; j++ {
			if grid[j][i] != 0 {
				grid2[j][i] = s[sIndex]
				sIndex++
			}
		}
	}

	sIndex = 0
	blockIndex := 0
	out: for sIndex < len(s) {
		blockPos := blockIndex * len(key)
		for i, ki := range keyIndices {
			for j := 0; j < len(key); j++ {
				result = append(result, grid2[i + blockPos][j])
				sIndex++

				if sIndex >= len(s) {
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

						if sIndex >= len(s) {
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