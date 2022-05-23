package classical

import (
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

func sortKey(key string) ([]int, map[int]rune) {
	rKey := []rune(key)
	rKeyIndices := make([]int, len(key))
	keyMap := make(map[int]rune)

	for i := 0; i < len(rKey); i++ {
		keyMap[i] = rKey[i]
		rKeyIndices[i] = i;
	}

	sort.SliceStable(rKeyIndices, func(i, j int) bool {
		return keyMap[rKeyIndices[i]] < keyMap[rKeyIndices[j]]
	})

	return rKeyIndices, keyMap
}

func encryptColumn(s string, key string) string {
	keySize := len(key)
	rs := []rune(s)
	result := make([]rune, 0, len(s))
	rKeyIndices, _ := sortKey(key)

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
	rKeyIndices, _ := sortKey(key)

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

// ----- ZIGZAG (RAILFENCE) -----
type KeyZigzag uint
type Zigzag struct {
	Data *CipherClassicalData[KeyZigzag]
}

func (c *Zigzag) GetText() string { return c.Data.Text }
func (c *Zigzag) Encrypt() { c.Data.Text = encryptZigzag(c.Data.Text, c.Data.Key) }
func (c *Zigzag) Decrypt() { c.Data.Text = decryptZigzag(c.Data.Text, c.Data.Key) }

func encryptZigzag(s string, key *KeyZigzag) string {
	if *key <= 1 {
		return s
	}

	rs := []rune(s)
	result := make([]rune, len(s))
	d1 := 2 * (int(*key) - 1)
	d2 := 0
	rIndex := 0

	for i := 0; i < int(*key); i++ {
		j := i

		for j < len(s) {
			if d1 != 0 {
				result[rIndex] = rs[j]
				j += d1
				rIndex++
			}

			if d2 != 0 && j < len(s) {
				result[rIndex] = rs[j]
				j += d2
				rIndex++
			}
		}

		d1 -= 2
		d2 += 2
	}

	return string(result)
}

func decryptZigzag(s string, key *KeyZigzag) string {
	if *key <= 1 {
		return s
	}

	rs := []rune(s)
	result := make([]rune, len(s))
	d1 := 2 * (int(*key) - 1)
	d2 := 0
	rIndex := 0

	for i := 0; i < int(*key); i++ {
		j := i

		for j < len(s) {
			if d1 != 0 {
				result[j] = rs[rIndex]
				j += d1
				rIndex++
			}

			if d2 != 0 && j < len(s) {
				result[j] = rs[rIndex]
				j += d2
				rIndex++
			}
		}

		d1 -= 2
		d2 += 2
	}

	return string(result)
}

// ----- SCYTALE (SKYTALE) -----
type KeyScytale uint
type Scytale struct {
	Data *CipherClassicalData[KeyScytale]
}

func (c *Scytale) GetText() string { return c.Data.Text }
func (c *Scytale) Encrypt() { c.Data.Text = encryptScytale(c.Data.Text, c.Data.Key) }
func (c *Scytale) Decrypt() { c.Data.Text = decryptScytale(c.Data.Text, c.Data.Key) }

func encryptScytale(s string, key *KeyScytale) string {
	if *key <= 1 {
		return s
	}

	rs := []rune(s)
	result := make([]rune, len(s))
	rIndex := 0

	for i := 0; i < int(*key); i++ {
		j := i

		for j < len(s) {
			result[rIndex] = rs[j]
			j += int(*key)
			rIndex++
		}
	}

	return string(result)
}

func decryptScytale(s string, key *KeyScytale) string {
	if *key <= 1 {
		return s
	}

	rs := []rune(s)
	result := make([]rune, len(s))
	rIndex := 0

	for i := 0; i < int(*key); i++ {
		j := i

		for j < len(s) {
			result[j] = rs[rIndex]
			j += int(*key)
			rIndex++
		}
	}

	return string(result)
}

// ----- ROUTE -----
const (
	up complex128 	= 0 + 1i
	right			= 1 + 0i
	down			= 0 - 1i
	left			= -1 + 0i
)

const (
	topleft complex128 	= 0 + 0i
	topright			= 1 + 0i
	bottomright			= 1 + 1i
	bottomleft			= 0 + 1i
)

const (
	clockwise complex128 	= 0 - 1i
	c_clockwise				= 0 + 1i
)

type routeType int
const (
	routeTypeSpiral routeType = iota
	routeTypeSerpent
)

type route struct {
	corner 		complex128
	direction 	complex128
	rotation 	complex128
}
var ROUTE_TLR = route{topleft, right, clockwise}
var ROUTE_TLD = route{topleft, down, c_clockwise}
var ROUTE_TRL = route{topright, left, c_clockwise}
var ROUTE_TRD = route{topright, down, clockwise}
var ROUTE_BLR = route{bottomleft, right, c_clockwise}
var ROUTE_BLU = route{bottomleft, up, clockwise}
var ROUTE_BRL = route{bottomright, left, clockwise}
var ROUTE_BRU = route{bottomright, up, c_clockwise}

type KeyRoute struct {
	Width uint
	Route route
}

func cryptRoute(s string, key *KeyRoute, route routeType, encrypt bool) string {
	rs := []rune(s)
	result := make([]rune, len(s))
	rows := int(math.Ceil(float64(len(s)) / float64(key.Width)))
	cols := int(key.Width)
	i := int(imag(key.Route.corner)) * (rows - 1)
	j := int(real(key.Route.corner)) * int(cols - 1)
	direction := key.Route.direction
	rotation := key.Route.rotation
	rIndex := 0

	switch route {
	case routeTypeSpiral:
		for rows > 0 && cols > 0 {
			if (imag(direction) != 0) {
				for r := 0; r < rows; r++ {
					index := j + i * int(key.Width)
					if index < len(rs) {
						if encrypt {
							result[rIndex] = rs[index]
						} else {
							result[index] = rs[rIndex]
						}
						rIndex++
					}
					i -= int(imag(direction))
				}
				cols--
				i += int(imag(direction))
			} else {
				for c := 0; c < cols; c++ {
					index := j + i * int(key.Width)
					if index < len(rs) {
						if encrypt {
							result[rIndex] = rs[index]
						} else {
							result[index] = rs[rIndex]
						}
						rIndex++
					}
					j += int(real(direction))
				}
				rows--
				j -= int(real(direction))
			}
	
			direction *= key.Route.rotation
			i -= int(imag(direction))
			j += int(real(direction))
		}
	case routeTypeSerpent:
		for rows > 0 && cols > 0 {
			if (imag(direction) != 0) {
				for r := 0; r < rows; r++ {
					index := j + i * int(key.Width)
					if index < len(s) {
						if encrypt {
							result[rIndex] = rs[index]
						} else {
							result[index] = rs[rIndex]
						}
						rIndex++
					}
					i -= int(imag(direction))
				}
				cols--
				i += int(imag(direction))
			} else {
				for c := 0; c < cols; c++ {
					index := j + i * int(key.Width)
					if index < len(rs) {
						if encrypt {
							result[rIndex] = rs[index]
						} else {
							result[index] = rs[rIndex]
						}
						rIndex++
					}
					j += int(real(direction))
				}
				rows--
				j -= int(real(direction))
			}
	
			direction *= rotation
			i -= int(imag(direction))
			j += int(real(direction))
			direction *= rotation
			rotation *= -1
		}
	}

	return string(result)
}

// ----- ROUTE SPIRAL -----
type RouteSpiral struct {
	Data *CipherClassicalData[KeyRoute]
}

func (c *RouteSpiral) GetText() string { return c.Data.Text }
func (c *RouteSpiral) Encrypt() { c.Data.Text = cryptRoute(c.Data.Text, c.Data.Key, routeTypeSpiral, true); }
func (c *RouteSpiral) Decrypt() { c.Data.Text = cryptRoute(c.Data.Text, c.Data.Key, routeTypeSpiral, false); }

// ----- ROUTE SERPENT -----
type RouteSerpent struct {
	Data *CipherClassicalData[KeyRoute]
}

func (c *RouteSerpent) GetText() string { return c.Data.Text }
func (c *RouteSerpent) Encrypt() { c.Data.Text = cryptRoute(c.Data.Text, c.Data.Key, routeTypeSerpent, true) }
func (c *RouteSerpent) Decrypt() { c.Data.Text = cryptRoute(c.Data.Text, c.Data.Key, routeTypeSerpent, false) }

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
	rKeyIndices, keyMap := sortKey(key)

	rows := int(math.Ceil(float64(len(s)) / float64(keySize)))
	for i := 0; i < len(rKeyIndices); i++ { 
		equivalent := 0
		for j := 1; i + j < len(rKeyIndices); j++ {
			if keyMap[rKeyIndices[i + j]] == keyMap[rKeyIndices[i]] {
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
	rKeyIndices, keyMap := sortKey(key)

	rows := int(math.Ceil(float64(len(s)) / float64(keySize)))
	sIndex := 0
	for i := 0; i < len(rKeyIndices); i++ { 
		equivalent := 0
		for j := 1; i + j < len(rKeyIndices); j++ {
			if keyMap[rKeyIndices[i + j]] == keyMap[rKeyIndices[i]] {
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

// ----- MAGNET -----
type KeyMagnet struct {}
type Magnet struct {
	Data *CipherClassicalData[KeyMagnet]
}

func (c *Magnet) GetText() string { return c.Data.Text }
func (c *Magnet) Encrypt() { c.Data.Text = encryptMagnet(c.Data.Text) }
func (c *Magnet) Decrypt() { c.Data.Text = decryptMagnet(c.Data.Text) }

func encryptMagnet(s string) string {
	rs := []rune(s)
	result := make([]rune, len(s))
	mid := len(s) / 2
	rIndex := 0

	for i := 0; i < mid; i++ {
		result[rIndex] = rs[i]
		result[rIndex + 1] = rs[len(s) - i - 1]
		rIndex += 2
	}

	if len(s) % 2 != 0 {
		result[rIndex] = rs[mid]
	}

	return string(result)
}

func decryptMagnet(s string) string {
	rs := []rune(s)
	result := make([]rune, len(s))
	mid := len(s) / 2
	rIndex := 0

	for i := 0; i < mid; i++ {
		result[i] = rs[rIndex]
		result[len(s) - i - 1] = rs[rIndex + 1]
		rIndex += 2
	}

	if len(s) % 2 != 0 {
		result[mid] = rs[rIndex]
	}

	return string(result)
}

// ----- ELASTIC (reverse magnet) -----
type KeyElastic struct {}
type Elastic struct {
	Data *CipherClassicalData[KeyElastic]
}

func (c *Elastic) GetText() string { return c.Data.Text }
func (c *Elastic) Encrypt() { c.Data.Text = encryptElastic(c.Data.Text) }
func (c *Elastic) Decrypt() { c.Data.Text = decryptElastic(c.Data.Text) }

func encryptElastic(s string) string {
	rs := []rune(s)
	result := make([]rune, len(s))
	mid := len(s) / 2
	diff := 0
	rIndex := 0

	if len(s) % 2 != 0 {
		result[rIndex] = rs[mid]
		rIndex++
		diff = 1
	}

	for i := 0; i < mid; i++ {
		result[rIndex] = rs[mid - i - 1]
		result[rIndex + 1] = rs[mid + i + diff]
		rIndex += 2
	}

	return string(result)
}

func decryptElastic(s string) string {
	rs := []rune(s)
	result := make([]rune, len(s))
	mid := len(s) / 2
	diff := 0
	rIndex := 0

	if len(s) % 2 != 0 {
		result[mid] = rs[rIndex]
		rIndex++
		diff = 1
	}

	for i := 0; i < mid; i++ {
		result[mid - i - 1] = rs[rIndex]
		result[mid + i + diff] = rs[rIndex + 1]
		rIndex += 2
	}

	return string(result)
}

// ----- COLUMN DISRUPTED LINE -----
/*type KeyColumnDisruptedLine string
type ColumnDisruptedLine struct {
	Data *CipherClassicalData[KeyColumnDisruptedLine]
}

func (c *ColumnDisruptedLine) GetText() string { return c.Data.Text }
func (c *ColumnDisruptedLine) Encrypt() { c.Data.Text = encryptColumnDisruptedLine(c.Data.Text, string(*c.Data.Key)) }
func (c *ColumnDisruptedLine) Decrypt() { c.Data.Text = decryptColumnDisruptedLine(c.Data.Text, string(*c.Data.Key)) }

func encryptColumnDisruptedLine(s string, key string) string {

}

func decryptColumnDisruptedLine(s string, key string) string {

}

// ----- COLUMN DISRUPTED COUNT -----
type KeyColumnDisruptedCount string
type ColumnDisruptedCount struct {
	Data *CipherClassicalData[KeyColumnDisruptedCount]
}

func (c *ColumnDisruptedCount) GetText() string { return c.Data.Text }
func (c *ColumnDisruptedCount) Encrypt() { c.Data.Text = encryptColumnDisruptedCount(c.Data.Text, string(*c.Data.Key)) }
func (c *ColumnDisruptedCount) Decrypt() { c.Data.Text = decryptColumnDisruptedCount(c.Data.Text, string(*c.Data.Key)) }

func encryptColumnDisruptedCount(s string, key string) string {

}

func decryptColumnDisruptedCount(s string, key string) string {

}*/
