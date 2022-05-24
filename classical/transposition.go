package classical

import (
	"math"
)

// ----- REVERSE -----
type KeyReverse struct {}
type Reverse struct {
	Data *CipherClassicalData[KeyReverse]
}

func (c *Reverse) GetText() string { return c.Data.Text }
func (c *Reverse) Encrypt() { c.Data.Text = reverse(c.Data.Text) }
func (c *Reverse) Decrypt() { c.Data.Text = reverse(c.Data.Text) }

func reverse(s string) string {
	rs := []rune(s)

	for i, j := 0, len(rs) - 1; i < j; i, j = i + 1, j - 1 {
		rs[i], rs[j] = rs[j], rs[i]
	}

	return string(rs)
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
	if *key < 2 {
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
	if *key < 2 {
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
	if *key < 2 {
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
	if *key < 2 {
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
