package classical

import (
	"cryptochev/utils"
	"math"
)

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

func NewReverse(text []rune) *Reverse { return &Reverse{Cipher: &CipherClassical[KeyNone]{Text: text, Key: &KeyNone{}}} }

type Reverse struct { Cipher *CipherClassical[KeyNone] }
func (c *Reverse) GetText() []rune { return c.Cipher.Text }
func (c *Reverse) GetErrors() []error { return c.Cipher.Errors }
func (c *Reverse) Encrypt() { c.Cipher.Text = reverse(c.Cipher.Text) }
func (c *Reverse) Decrypt() { c.Cipher.Text = reverse(c.Cipher.Text) }
func (c *Reverse) Verify() bool { return true }

func reverse(text []rune) []rune {
	for i, j := 0, len(text) - 1; i < j; i, j = i + 1, j - 1 {
		text[i], text[j] = text[j], text[i]
	}

	return text
}

func NewKeyZigzag(lines int) *KeyZigzag { return &KeyZigzag{Lines: lines} }
func NewZigzag(text []rune, key *KeyZigzag) *Zigzag { return &Zigzag{Cipher: &CipherClassical[KeyZigzag]{Text: text, Key: key}} }

type KeyZigzag struct { 
	Lines int 
}

type Zigzag struct { Cipher *CipherClassical[KeyZigzag] }
func (c *Zigzag) GetText() []rune { return c.Cipher.Text }
func (c *Zigzag) GetErrors() []error { return c.Cipher.Errors }
func (c *Zigzag) Encrypt() { c.Cipher.Text = cryptZigzag(c.Cipher.Text, c.Cipher.Key.Lines, true) }
func (c *Zigzag) Decrypt() { c.Cipher.Text = cryptZigzag(c.Cipher.Text, c.Cipher.Key.Lines, false) }
func (c *Zigzag) Verify() bool { return true }

func cryptZigzag(text []rune, lines int, encrypt bool) []rune {
	if lines < 2 {
		return text
	}

	result := make([]rune, len(text))
	d1 := 2 * (lines - 1)
	d2 := 0
	sIndex := 0

	for i := 0; i < lines; i++ {
		j := i

		for j < len(text) {
			if d1 != 0 {
				i1, i2 := utils.SwapIf(j, sIndex, encrypt)
				result[i1] = text[i2]
				j += d1
				sIndex++
			}

			if d2 != 0 && j < len(text) {
				i1, i2 := utils.SwapIf(j, sIndex, encrypt)
				result[i1] = text[i2]
				j += d2
				sIndex++
			}
		}

		d1 -= 2
		d2 += 2
	}

	return result
}

func NewKeyScytale(lines int) *KeyScytale { return &KeyScytale{Lines: lines} }
func NewScytale(text []rune, key *KeyScytale) *Scytale { return &Scytale{Cipher: &CipherClassical[KeyScytale]{Text: text, Key: key}} }

type KeyScytale struct { 
	Lines int
}

type Scytale struct { Cipher *CipherClassical[KeyScytale] }
func (c *Scytale) GetText() []rune { return c.Cipher.Text }
func (c *Scytale) GetErrors() []error { return c.Cipher.Errors }
func (c *Scytale) Encrypt() { c.Cipher.Text = cryptScytale(c.Cipher.Text, c.Cipher.Key.Lines, true) }
func (c *Scytale) Decrypt() { c.Cipher.Text = cryptScytale(c.Cipher.Text, c.Cipher.Key.Lines, false) }
func (c *Scytale) Verify() bool { return true }

func cryptScytale(text []rune, lines int, encrypt bool) []rune {
	if lines < 2 {
		return text
	}

	result := make([]rune, len(text))
	sIndex := 0

	for i := 0; i < lines; i++ {
		j := i

		for j < len(text) {
			i1, i2 := utils.SwapIf(j, sIndex, encrypt)
			result[i1] = text[i2]
			j += lines
			sIndex++
		}
	}

	return result
}

func NewKeyRoute(width int, r route) *KeyRoute { return &KeyRoute{Width: width, Route: r} }
func NewRouteSpiral(text []rune, key *KeyRoute) *RouteSpiral { return &RouteSpiral{Cipher: &CipherClassical[KeyRoute]{Text: text, Key: key}} }

type KeyRoute struct { 
	Width int 
	Route route
}

type RouteSpiral struct { Cipher *CipherClassical[KeyRoute] }
func (c *RouteSpiral) GetText() []rune { return c.Cipher.Text }
func (c *RouteSpiral) GetErrors() []error { return c.Cipher.Errors }
func (c *RouteSpiral) Encrypt() { c.Cipher.Text = cryptRoute(c.Cipher.Text, c.Cipher.Key.Width, c.Cipher.Key.Route, routeTypeSpiral, true); }
func (c *RouteSpiral) Decrypt() { c.Cipher.Text = cryptRoute(c.Cipher.Text, c.Cipher.Key.Width, c.Cipher.Key.Route, routeTypeSpiral, false); }
func (c *RouteSpiral) Verify() bool { return true }

func NewRouteSerpent(text []rune, key *KeyRoute) *RouteSerpent {
	return &RouteSerpent{Cipher: &CipherClassical[KeyRoute]{Text: text, Key: key}}
}

type RouteSerpent struct { Cipher *CipherClassical[KeyRoute] }
func (c *RouteSerpent) GetText() []rune { return c.Cipher.Text }
func (c *RouteSerpent) GetErrors() []error { return c.Cipher.Errors }
func (c *RouteSerpent) Encrypt() { c.Cipher.Text = cryptRoute(c.Cipher.Text, c.Cipher.Key.Width, c.Cipher.Key.Route, routeTypeSerpent, true) }
func (c *RouteSerpent) Decrypt() { c.Cipher.Text = cryptRoute(c.Cipher.Text, c.Cipher.Key.Width, c.Cipher.Key.Route, routeTypeSerpent, false) }
func (c *RouteSerpent) Verify() bool { return true }

func cryptRoute(text []rune, width int, r route, rt routeType, encrypt bool) []rune {
	result := make([]rune, len(text))
	rows := int(math.Ceil(float64(len(text)) / float64(width)))
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
					if index < len(text) {
						i1, i2 := utils.SwapIf(index, sIndex, encrypt)
						result[i1] = text[i2]
						sIndex++
					}
					i -= int(imag(direction))
				}
				cols--
				i += int(imag(direction))
			} else {
				for c := 0; c < cols; c++ {
					index := j + i * width
					if index < len(text) {
						i1, i2 := utils.SwapIf(index, sIndex, encrypt)
						result[i1] = text[i2]
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
					if index < len(text) {
						i1, i2 := utils.SwapIf(index, sIndex, encrypt)
						result[i1] = text[i2]
						sIndex++
					}
					i -= int(imag(direction))
				}
				cols--
				i += int(imag(direction))
			} else {
				for c := 0; c < cols; c++ {
					index := j + i * width
					if index < len(text) {
						i1, i2 := utils.SwapIf(index, sIndex, encrypt)
						result[i1] = text[i2]
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

	return result
}

func NewMagnet(text []rune) *Magnet { return &Magnet{Cipher: &CipherClassical[KeyNone]{Text: text, Key: &KeyNone{}}} }

type Magnet struct { Cipher *CipherClassical[KeyNone] }
func (c *Magnet) GetText() []rune { return c.Cipher.Text }
func (c *Magnet) GetErrors() []error { return c.Cipher.Errors }
func (c *Magnet) Encrypt() { c.Cipher.Text = cryptMagnet(c.Cipher.Text, true) }
func (c *Magnet) Decrypt() { c.Cipher.Text = cryptMagnet(c.Cipher.Text, false) }
func (c *Magnet) Verify() bool { return true }

func cryptMagnet(text []rune, encrypt bool) []rune {
	result := make([]rune, len(text))
	mid := len(text) / 2
	sIndex := 0

	for i := 0; i < mid; i++ {
		i1, i2 := utils.SwapIf(i, sIndex, encrypt)
		result[i1] = text[i2]
		i1, i2 = utils.SwapIf(len(text) - i - 1, sIndex + 1, encrypt)
		result[i1] = text[i2]
		sIndex += 2
	}

	if len(text) % 2 != 0 {
		i1, i2 := utils.SwapIf(mid, sIndex, encrypt)
		result[i1] = text[i2]
	}

	return result
}

func NewElastic(text []rune) *Elastic { return &Elastic{Cipher: &CipherClassical[KeyNone]{Text: text, Key: &KeyNone{}}} }

type Elastic struct { Cipher *CipherClassical[KeyNone] }
func (c *Elastic) GetText() []rune { return c.Cipher.Text }
func (c *Elastic) GetErrors() []error { return c.Cipher.Errors }
func (c *Elastic) Encrypt() { c.Cipher.Text = cryptElastic(c.Cipher.Text, true) }
func (c *Elastic) Decrypt() { c.Cipher.Text = cryptElastic(c.Cipher.Text, false) }
func (c *Elastic) Verify() bool { return true }

func cryptElastic(text []rune, encrypt bool) []rune {
	result := make([]rune, len(text))
	mid := len(text) / 2
	diff := 0
	sIndex := 0

	if len(text) % 2 != 0 {
		i1, i2 := utils.SwapIf(mid, sIndex, encrypt)
		result[i1] = text[i2]
		sIndex++
		diff = 1
	}

	for i := 0; i < mid; i++ {
		i1, i2 := utils.SwapIf(mid - i - 1, sIndex, encrypt)
		result[i1] = text[i2]
		i1, i2 = utils.SwapIf(mid + i + diff, sIndex + 1, encrypt)
		result[i1] = text[i2]
		sIndex += 2
	}

	return result
}
