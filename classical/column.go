package classical

import (
	"cryptochev/utils"
	"math"
	"sort"
)

// ----- COLUMN -----
type KeyColumn string
type Column struct {
	Data *CipherClassicalData[KeyColumn]
}

func (c *Column) GetText() string { return c.Data.Text }
func (c *Column) Encrypt() { c.Data.Text = encryptColumn(c.Data.Text, string(*c.Data.Key)) }
func (c *Column) Decrypt() { c.Data.Text = decryptColumn(c.Data.Text, string(*c.Data.Key)) }

func getSortedKeyIndices(key string) []int {
	rKey := []rune(key)
	rKeyIndices := make([]int, len(key))
	for i := 0; i < len(rKey); i++ {
		rKeyIndices[i] = i;
	}

	sort.SliceStable(rKeyIndices, func(i, j int) bool {
		return rKey[rKeyIndices[i]] < rKey[rKeyIndices[j]]
	})

	return rKeyIndices
}

func encryptColumn(s string, key string) string {
	keySize := len(key)
	rs := []rune(s)
	result := make([]rune, 0, len(s))
	rKeyIndices := getSortedKeyIndices(key)

	rows := int(math.Ceil(float64(len(s)) / float64(keySize)))
	for _, i := range rKeyIndices {
		for j := 0; j < rows; j++ {
			index := i + j * keySize
			if index < len(s) {
				result = append(result, rs[index])
			}
		}
	}

	return string(result)
}

func decryptColumn(s string, key string) string {
	keySize := len(key)
	rs := []rune(s)
	result := make([]rune, len(s))
	rKeyIndices := getSortedKeyIndices(key)

	rows := int(math.Ceil(float64(len(s)) / float64(keySize)))
	sIndex := 0
	for _, i := range rKeyIndices {
		for j := 0; j < rows; j++ {
			index := i + j * keySize
			if index < len(s) {
				result[index] = rs[sIndex]
				sIndex++
			}
		}
	}

	return string(result)
}

// ----- MYSZKOWSKI -----
type KeyMyszkowski string
type Myszkowski struct {
	Data *CipherClassicalData[KeyMyszkowski]
}

func (c *Myszkowski) GetText() string { return c.Data.Text }
func (c *Myszkowski) Encrypt() { c.Data.Text = encryptMyszkowski(c.Data.Text, string(*c.Data.Key)) }
func (c *Myszkowski) Decrypt() { c.Data.Text = decryptMyszkowski(c.Data.Text, string(*c.Data.Key)) }

func encryptMyszkowski(s string, key string) string {
	keySize := len(key)
	rs := []rune(s)
	result := make([]rune, 0, len(s))
	rKey := []rune(key)
	rKeyIndices := getSortedKeyIndices(key)

	rows := int(math.Ceil(float64(len(s)) / float64(keySize)))
	for i := 0; i < len(rKeyIndices); i++ { 
		equivalent := 0
		for j := 1; i + j < len(rKeyIndices); j++ {
			if rKey[rKeyIndices[i + j]] == rKey[rKeyIndices[i]] {
				equivalent++
			} else {
				break
			}
		} 

		for j := 0; j < rows; j++ {
			for k := 0; k < equivalent + 1; k++ {
				index := rKeyIndices[i + k] + j * keySize
				if index < len(s) {
					result = append(result, rs[index])
				}
			}
		}

		i += equivalent
	}

	return string(result)
}

func decryptMyszkowski(s string, key string) string {
	keySize := len(key)
	rs := []rune(s)
	result := make([]rune, len(s))
	rKey := []rune(key)
	rKeyIndices := getSortedKeyIndices(key)

	rows := int(math.Ceil(float64(len(s)) / float64(keySize)))
	sIndex := 0
	for i := 0; i < len(rKeyIndices); i++ { 
		equivalent := 0
		for j := 1; i + j < len(rKeyIndices); j++ {
			if rKey[rKeyIndices[i + j]] == rKey[rKeyIndices[i]] {
				equivalent++
			} else {
				break
			}
		}

		for j := 0; j < rows; j++ {
			for k := 0; k < equivalent + 1; k++ {
				index := rKeyIndices[i + k] + j * keySize
				if index < len(s) {
					result[index] = rs[sIndex]
					sIndex++
				}
			}
		}

		i += equivalent
	}

	return string(result)
}

func getSortedKeyPositions(key string) []int {
	rKey := []rune(key)
	rKeyPositions := make([]int, len(key))
	rKeyIndices := make([]int, len(key))
	for i := 0; i < len(rKey); i++ {
		rKeyIndices[i] = i;
	}

	sort.SliceStable(rKeyIndices, func(i, j int) bool {
		return rKey[rKeyIndices[i]] < rKey[rKeyIndices[j]]
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

// ----- COLUMN DISRUPTED COUNT -----
type KeyColumnDCount struct {
	CKey string
	DKey string
}

type ColumnDCount struct {
	Data *CipherClassicalData[KeyColumnDCount]
}

func (c *ColumnDCount) GetText() string { return c.Data.Text }
func (c *ColumnDCount) Encrypt() { c.Data.Text = encryptColumnDCount(c.Data.Text, c.Data.Key.CKey, c.Data.Key.DKey) }
func (c *ColumnDCount) Decrypt() { c.Data.Text = decryptColumnDCount(c.Data.Text, c.Data.Key.CKey, c.Data.Key.DKey) }

func encryptColumnDCount(s string, key string, dkey string) string {
	if len(dkey) < 2 {
		return s
	}

	keySize := len(key)
	rs := []rune(s)
	result := make([]rune, 0, len(s))
	rKeyIndices := getSortedKeyIndices(key)
	rKeyPositions := getSortedKeyPositions(dkey)
	gaps := 0
	gapPos := 0

	for gapPos < len(s) + gaps {
		for _, p := range rKeyPositions {
			gapPos += p
			if gapPos < len(s) + gaps {
				gaps++
				gapPos++
			} else {
				break
			}
		}
	}

	rows := int(math.Ceil(float64(len(s) + gaps) / float64(keySize)))
	gapCount := 0
	posIndex := 0
	nextGap := rKeyPositions[0]
	grid := make([][]rune, rows)
	for i := range grid {
		grid[i] = make([]rune, keySize)
	}

	for i := 0; i < rows; i++ {
		for j := 0; j < keySize; j++ {
			index := j + i * keySize
			if index == nextGap {
				posIndex++
				if posIndex >= len(rKeyPositions) {
					posIndex = 0
				}
				nextGap += rKeyPositions[posIndex] + 1
				gapCount++
			} else if index - gapCount < len(s) {
				grid[i][j] = rs[index - gapCount]
			} else {
				break
			}
		}
	}

	for _, i := range rKeyIndices {
		for j := 0; j < rows; j++ {
			if grid[j][i] != 0 {
				result = append(result, grid[j][i])
			}
		}
	}

	return string(result)
}

func decryptColumnDCount(s string, key string, dkey string) string {
	if len(dkey) < 2 {
		return s
	}

	keySize := len(key)
	rs := []rune(s)
	result := make([]rune, 0, len(s))
	rKeyIndices := getSortedKeyIndices(key)
	rKeyPositions := getSortedKeyPositions(dkey)
	gaps := 0
	gapPos := 0
	gapIndices := make([]int, 0, int(math.Ceil(float64(triangleNumber(keySize)) / float64(triangleNumber(keySize - 1)) * float64(len(s)))))

	for gapPos < len(s) + gaps {
		for _, p := range rKeyPositions {
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

	rows := int(math.Ceil(float64(len(s) + gaps) / float64(keySize)))
	sIndex := 0
	grid := make([][]rune, rows)
	for i := range grid {
		grid[i] = make([]rune, keySize)
	}

	for _, i := range rKeyIndices {
		for j := 0; j < rows; j++ {
			index := i + j * keySize
			if !utils.Contains(gapIndices, index) && index < len(s) + gaps && sIndex < len(s) {
				grid[j][i] = rs[sIndex]
				sIndex++
			}
		}
	}

	for i := 0; i < rows; i++ {
		for j := 0; j < keySize; j++ {
			if grid[i][j] != 0 {
				result = append(result, grid[i][j])
			}
		}
	}

	return string(result)
}

// ----- COLUMN DISRUPTED LINE -----
type KeyColumnDLine struct {
	Key string
	Fill bool
}

type ColumnDLine struct {
	Data *CipherClassicalData[KeyColumnDLine]
}

func (c *ColumnDLine) GetText() string { return c.Data.Text }
func (c *ColumnDLine) Encrypt() { c.Data.Text = encryptColumnDLine(c.Data.Text, c.Data.Key.Key, c.Data.Key.Fill) }
func (c *ColumnDLine) Decrypt() { c.Data.Text = decryptColumnDLine(c.Data.Text, c.Data.Key.Key, c.Data.Key.Fill) }

func buildDLineGrid(rs []rune, rKeyIndices []int, keySize int, fill bool) ([][]rune, int) {
	block := 0
	if fill {
		block = keySize * keySize
	} else {
		block = triangleNumber(keySize)
	}
	blocks := int(math.Ceil(float64(len(rs)) / float64(block)))
	rows := blocks * keySize

	grid := make([][]rune, rows)
	for i := range grid {
		grid[i] = make([]rune, keySize)
	}
	
	sIndex := 0
	blockIndex := 0
	out: for sIndex < len(rs) {
		blockPos := blockIndex * keySize
		for i, ki := range rKeyIndices {
			for j := 0; j < keySize; j++ {
				grid[i + blockPos][j] = rs[sIndex]
				sIndex++

				if sIndex >= len(rs) {
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
						grid[i][j] = rs[sIndex]
						sIndex++

						if sIndex >= len(rs) {
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

func encryptColumnDLine(s string, key string, fill bool) string {
	if len(key) < 2 {
		return s
	}

	keySize := len(key)
	rs := []rune(s)
	result := make([]rune, 0, len(s))
	rKeyIndices := getSortedKeyIndices(key)
	grid, rows := buildDLineGrid(rs, rKeyIndices, keySize, fill)

	for _, i := range rKeyIndices {
		for j := 0; j < rows; j++ {
			if grid[j][i] != 0 {
				result = append(result, grid[j][i])
			}
		}
	}

	return string(result)
}

func decryptColumnDLine(s string, key string, fill bool) string {
	if len(key) < 2 {
		return s
	}

	keySize := len(key)
	rs := []rune(s)
	result := make([]rune, 0, len(s))
	rKeyIndices := getSortedKeyIndices(key)
	grid, rows := buildDLineGrid(rs, rKeyIndices, keySize, fill)

	grid2 := make([][]rune, rows)
	for i := range grid2 {
		grid2[i] = make([]rune, keySize)
	}

	sIndex := 0
	for _, i := range rKeyIndices {
		for j := 0; j < rows; j++ {
			if grid[j][i] != 0 {
				grid2[j][i] = rs[sIndex]
				sIndex++
			}
		}
	}

	sIndex = 0
	blockIndex := 0
	out: for sIndex < len(rs) {
		blockPos := blockIndex * keySize
		for i, ki := range rKeyIndices {
			for j := 0; j < keySize; j++ {
				result = append(result, grid2[i + blockPos][j])
				sIndex++

				if sIndex >= len(rs) {
					break out
				} else if j == ki {
					break
				}
			}
		}

		if fill {
			for i, ki := range rKeyIndices {
				for j := 0; j < keySize; j++ {
					if grid2[i + blockPos][j] != 0 && j > ki {
						result = append(result, grid2[i + blockPos][j])
						sIndex++

						if sIndex >= len(rs) {
							break out
						}
					}
				}
			}
		}

		blockIndex++
	}

	return string(result)
}