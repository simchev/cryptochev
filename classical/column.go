package classical

import (
	"cryptochev/utils"
	"math"
	"sort"
)

type KeyColumn string
type Column struct {
	Data *CipherClassicalData[KeyColumn]
}

func (c *Column) GetText() string { return c.Data.Text }
func (c *Column) Encrypt() { c.Data.Text = cryptColumn(c.Data.Text, string(*c.Data.Key), true) }
func (c *Column) Decrypt() { c.Data.Text = cryptColumn(c.Data.Text, string(*c.Data.Key), false) }

func getSortedKeyIndices(key string) []int {
	rKey := []rune(key)
	rKeyIndices := make([]int, len(rKey))
	for i := 0; i < len(rKey); i++ {
		rKeyIndices[i] = i;
	}

	sort.SliceStable(rKeyIndices, func(i, j int) bool {
		return rKey[rKeyIndices[i]] < rKey[rKeyIndices[j]]
	})

	return rKeyIndices
}

func cryptColumn(s string, key string, encrypt bool) string {
	rkey := []rune(key)
	rs := []rune(s)
	result := make([]rune, len(rs))
	rKeyIndices := getSortedKeyIndices(key)

	rows := int(math.Ceil(float64(len(rs)) / float64(len(rkey))))
	sIndex := 0
	for _, i := range rKeyIndices {
		for j := 0; j < rows; j++ {
			index := i + j * len(rkey)
			if index < len(rs) {
				i1, i2 := utils.ReverseIf(index, sIndex, encrypt)
				result[i1] = rs[i2]
				sIndex++
			}
		}
	}

	return string(result)
}

type KeyMyszkowski string
type Myszkowski struct {
	Data *CipherClassicalData[KeyMyszkowski]
}

func (c *Myszkowski) GetText() string { return c.Data.Text }
func (c *Myszkowski) Encrypt() { c.Data.Text = cryptMyszkowski(c.Data.Text, string(*c.Data.Key), true) }
func (c *Myszkowski) Decrypt() { c.Data.Text = cryptMyszkowski(c.Data.Text, string(*c.Data.Key), false) }

func cryptMyszkowski(s string, key string, encrypt bool) string {
	rkey := []rune(key)
	rs := []rune(s)
	result := make([]rune, len(rs))
	rKey := []rune(key)
	rKeyIndices := getSortedKeyIndices(key)

	rows := int(math.Ceil(float64(len(rs)) / float64(len(rkey))))
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
				index := rKeyIndices[i + k] + j * len(rkey)
				if index < len(rs) {
					i1, i2 := utils.ReverseIf(index, sIndex, encrypt)
					result[i1] = rs[i2]
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
	rKeyPositions := make([]int, len(rKey))
	rKeyIndices := make([]int, len(rKey))
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
	rdkey := []rune(dkey)
	if len(rdkey) < 2 {
		return s
	}

	rkey := []rune(key)
	rs := []rune(s)
	result := make([]rune, 0, len(rs))
	rKeyIndices := getSortedKeyIndices(key)
	rKeyPositions := getSortedKeyPositions(dkey)
	gaps := 0
	gapPos := 0

	for gapPos < len(rs) + gaps {
		for _, p := range rKeyPositions {
			gapPos += p
			if gapPos < len(rs) + gaps {
				gaps++
				gapPos++
			} else {
				break
			}
		}
	}

	rows := int(math.Ceil(float64(len(rs) + gaps) / float64(len(rkey))))
	gapCount := 0
	posIndex := 0
	nextGap := rKeyPositions[0]
	grid := make([][]rune, rows)
	for i := range grid {
		grid[i] = make([]rune, len(rkey))
	}

	for i := 0; i < rows; i++ {
		for j := 0; j < len(rkey); j++ {
			index := j + i * len(rkey)
			if index == nextGap {
				posIndex++
				if posIndex >= len(rKeyPositions) {
					posIndex = 0
				}
				nextGap += rKeyPositions[posIndex] + 1
				gapCount++
			} else if index - gapCount < len(rs) {
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
	rdkey := []rune(dkey)
	if len(rdkey) < 2 {
		return s
	}

	rkey := []rune(key)
	rs := []rune(s)
	result := make([]rune, 0, len(rs))
	rKeyIndices := getSortedKeyIndices(key)
	rKeyPositions := getSortedKeyPositions(dkey)
	gaps := 0
	gapPos := 0
	gapIndices := make([]int, 0, int(math.Ceil(float64(triangleNumber(len(rkey))) / float64(triangleNumber(len(rkey) - 1)) * float64(len(rs)))))

	for gapPos < len(rs) + gaps {
		for _, p := range rKeyPositions {
			gapPos += p
			if gapPos < len(rs) + gaps {
				gapIndices = append(gapIndices, gapPos)
				gaps++
				gapPos++
			} else {
				break
			}
		}
	}

	rows := int(math.Ceil(float64(len(rs) + gaps) / float64(len(rkey))))
	sIndex := 0
	grid := make([][]rune, rows)
	for i := range grid {
		grid[i] = make([]rune, len(rkey))
	}

	for _, i := range rKeyIndices {
		for j := 0; j < rows; j++ {
			index := i + j * len(rkey)
			if !utils.Contains(gapIndices, index) && index < len(rs) + gaps && sIndex < len(rs) {
				grid[j][i] = rs[sIndex]
				sIndex++
			}
		}
	}

	for i := 0; i < rows; i++ {
		for j := 0; j < len(rkey); j++ {
			if grid[i][j] != 0 {
				result = append(result, grid[i][j])
			}
		}
	}

	return string(result)
}

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
	rkey := []rune(key)
	if len(rkey) < 2 {
		return s
	}
	
	rs := []rune(s)
	result := make([]rune, 0, len(rs))
	rKeyIndices := getSortedKeyIndices(key)
	grid, rows := buildDLineGrid(rs, rKeyIndices, len(rkey), fill)

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
	rkey := []rune(key)
	if len(rkey) < 2 {
		return s
	}

	rs := []rune(s)
	result := make([]rune, 0, len(rs))
	rKeyIndices := getSortedKeyIndices(key)
	grid, rows := buildDLineGrid(rs, rKeyIndices, len(rkey), fill)

	grid2 := make([][]rune, rows)
	for i := range grid2 {
		grid2[i] = make([]rune, len(rkey))
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
		blockPos := blockIndex * len(rkey)
		for i, ki := range rKeyIndices {
			for j := 0; j < len(rkey); j++ {
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
				for j := 0; j < len(rkey); j++ {
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