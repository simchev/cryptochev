package classical

import (
	"cryptochev/utils"
	"math"
)

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

type KeyZigzag int
type Zigzag struct {
	Data *CipherClassicalData[KeyZigzag]
}

func (c *Zigzag) GetText() string { return c.Data.Text }
func (c *Zigzag) Encrypt() { c.Data.Text = cryptZigzag(c.Data.Text, int(*c.Data.Key), true) }
func (c *Zigzag) Decrypt() { c.Data.Text = cryptZigzag(c.Data.Text, int(*c.Data.Key), false) }

func cryptZigzag(s string, key int, encrypt bool) string {
	if key < 2 {
		return s
	}

	rs := []rune(s)
	result := make([]rune, len(s))
	d1 := 2 * (key - 1)
	d2 := 0
	sIndex := 0

	for i := 0; i < key; i++ {
		j := i

		for j < len(s) {
			if d1 != 0 {
				i1, i2 := utils.ReverseIf(j, sIndex, encrypt)
				result[i1] = rs[i2]
				j += d1
				sIndex++
			}

			if d2 != 0 && j < len(s) {
				i1, i2 := utils.ReverseIf(j, sIndex, encrypt)
				result[i1] = rs[i2]
				j += d2
				sIndex++
			}
		}

		d1 -= 2
		d2 += 2
	}

	return string(result)
}

type KeyScytale int
type Scytale struct {
	Data *CipherClassicalData[KeyScytale]
}

func (c *Scytale) GetText() string { return c.Data.Text }
func (c *Scytale) Encrypt() { c.Data.Text = cryptScytale(c.Data.Text, int(*c.Data.Key), true) }
func (c *Scytale) Decrypt() { c.Data.Text = cryptScytale(c.Data.Text, int(*c.Data.Key), false) }

func cryptScytale(s string, key int, encrypt bool) string {
	if key < 2 {
		return s
	}

	rs := []rune(s)
	result := make([]rune, len(s))
	sIndex := 0

	for i := 0; i < key; i++ {
		j := i

		for j < len(s) {
			i1, i2 := utils.ReverseIf(j, sIndex, encrypt)
			result[i1] = rs[i2]
			j += key
			sIndex++
		}
	}

	return string(result)
}

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
	Width int
	Route route
}

func cryptRoute(s string, width int, r route, rt routeType, encrypt bool) string {
	rs := []rune(s)
	result := make([]rune, len(s))
	rows := int(math.Ceil(float64(len(s)) / float64(width)))
	cols := width
	i := int(imag(r.corner)) * (rows - 1)
	j := int(real(r.corner)) * int(cols - 1)
	direction := r.direction
	rotation := r.rotation
	sIndex := 0

	switch rt {
	case routeTypeSpiral:
		for rows > 0 && cols > 0 {
			if (imag(direction) != 0) {
				for r := 0; r < rows; r++ {
					index := j + i * width
					if index < len(rs) {
						i1, i2 := utils.ReverseIf(index, sIndex, encrypt)
						result[i1] = rs[i2]
						sIndex++
					}
					i -= int(imag(direction))
				}
				cols--
				i += int(imag(direction))
			} else {
				for c := 0; c < cols; c++ {
					index := j + i * width
					if index < len(rs) {
						i1, i2 := utils.ReverseIf(index, sIndex, encrypt)
						result[i1] = rs[i2]
						sIndex++
					}
					j += int(real(direction))
				}
				rows--
				j -= int(real(direction))
			}
	
			direction *= r.rotation
			i -= int(imag(direction))
			j += int(real(direction))
		}
	case routeTypeSerpent:
		for rows > 0 && cols > 0 {
			if (imag(direction) != 0) {
				for r := 0; r < rows; r++ {
					index := j + i * width
					if index < len(s) {
						i1, i2 := utils.ReverseIf(index, sIndex, encrypt)
						result[i1] = rs[i2]
						sIndex++
					}
					i -= int(imag(direction))
				}
				cols--
				i += int(imag(direction))
			} else {
				for c := 0; c < cols; c++ {
					index := j + i * width
					if index < len(rs) {
						i1, i2 := utils.ReverseIf(index, sIndex, encrypt)
						result[i1] = rs[i2]
						sIndex++
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

type RouteSpiral struct {
	Data *CipherClassicalData[KeyRoute]
}

func (c *RouteSpiral) GetText() string { return c.Data.Text }
func (c *RouteSpiral) Encrypt() { c.Data.Text = cryptRoute(c.Data.Text, c.Data.Key.Width, c.Data.Key.Route, routeTypeSpiral, true); }
func (c *RouteSpiral) Decrypt() { c.Data.Text = cryptRoute(c.Data.Text, c.Data.Key.Width, c.Data.Key.Route, routeTypeSpiral, false); }

type RouteSerpent struct {
	Data *CipherClassicalData[KeyRoute]
}

func (c *RouteSerpent) GetText() string { return c.Data.Text }
func (c *RouteSerpent) Encrypt() { c.Data.Text = cryptRoute(c.Data.Text, c.Data.Key.Width, c.Data.Key.Route, routeTypeSerpent, true) }
func (c *RouteSerpent) Decrypt() { c.Data.Text = cryptRoute(c.Data.Text, c.Data.Key.Width, c.Data.Key.Route, routeTypeSerpent, false) }

type KeyMagnet struct {}
type Magnet struct {
	Data *CipherClassicalData[KeyMagnet]
}

func (c *Magnet) GetText() string { return c.Data.Text }
func (c *Magnet) Encrypt() { c.Data.Text = cryptMagnet(c.Data.Text, true) }
func (c *Magnet) Decrypt() { c.Data.Text = cryptMagnet(c.Data.Text, false) }

func cryptMagnet(s string, encrypt bool) string {
	rs := []rune(s)
	result := make([]rune, len(s))
	mid := len(s) / 2
	sIndex := 0

	for i := 0; i < mid; i++ {
		i1, i2 := utils.ReverseIf(i, sIndex, encrypt)
		result[i1] = rs[i2]
		i1, i2 = utils.ReverseIf(len(s) - i - 1, sIndex + 1, encrypt)
		result[i1] = rs[i2]
		sIndex += 2
	}

	if len(s) % 2 != 0 {
		i1, i2 := utils.ReverseIf(mid, sIndex, encrypt)
		result[i1] = rs[i2]
	}

	return string(result)
}

type KeyElastic struct {}
type Elastic struct {
	Data *CipherClassicalData[KeyElastic]
}

func (c *Elastic) GetText() string { return c.Data.Text }
func (c *Elastic) Encrypt() { c.Data.Text = cryptElastic(c.Data.Text, true) }
func (c *Elastic) Decrypt() { c.Data.Text = cryptElastic(c.Data.Text, false) }

func cryptElastic(s string, encrypt bool) string {
	rs := []rune(s)
	result := make([]rune, len(s))
	mid := len(s) / 2
	diff := 0
	sIndex := 0

	if len(s) % 2 != 0 {
		i1, i2 := utils.ReverseIf(mid, sIndex, encrypt)
		result[i1] = rs[i2]
		sIndex++
		diff = 1
	}

	for i := 0; i < mid; i++ {
		i1, i2 := utils.ReverseIf(mid - i - 1, sIndex, encrypt)
		result[i1] = rs[i2]
		i1, i2 = utils.ReverseIf(mid + i + diff, sIndex + 1, encrypt)
		result[i1] = rs[i2]
		sIndex += 2
	}

	return string(result)
}
