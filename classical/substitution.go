package classical

import "unicode"

// ----- SHIFT (unicode) -----
type KeyShift int
type Shift struct {
	Data *CipherClassicalData[KeyShift]
}

func (c *Shift) GetText() string { return c.Data.Text }
func (c *Shift) Encrypt() { c.Data.Text = shift(c.Data.Text, int(*c.Data.Key)) }
func (c *Shift) Decrypt() { c.Data.Text = shift(c.Data.Text, -int(*c.Data.Key)) }

func shift(s string, shift int) string {
	shifted := make([]rune, len(s))
	rshift := rune(shift)

	for i, r := range s {
		shifted[i] = r + rshift
	}

	return string(shifted)
}

// ----- CAESAR -----
type KeyCaesar int
type Caesar struct {
	Data *CipherClassicalData[KeyCaesar]
}

func (c *Caesar) GetText() string { return c.Data.Text }
func (c *Caesar) Encrypt() { c.Data.Text = shiftAlphabet(c.Data.Text, int(*c.Data.Key)) }
func (c *Caesar) Decrypt() { c.Data.Text = shiftAlphabet(c.Data.Text, -int(*c.Data.Key)) }

func shiftAlphabet(s string, shift int) string {
	shifted := []rune(s)
	rshift := rune(shift % 26)

	// Adjust latin letters if out of bound
	for i, r := range s {
		if unicode.IsUpper(r) {
			shifted[i] = r + rshift

			if shifted[i] < 65 {
				shifted[i] += 26
			} else if shifted[i] > 90 {
				shifted[i] -= 26
			}
		} else if unicode.IsLower(r) {
			shifted[i] = r + rshift

			if shifted[i] < 97 {
				shifted[i] += 26
			} else if shifted[i] > 122 {
				shifted[i] -= 26
			}
		}
	}

	return string(shifted)
}

// ----- ROT13 -----
type KeyROT13 struct {}
type ROT13 struct {
	Data *CipherClassicalData[KeyROT13]
}

func (c *ROT13) GetText() string { return c.Data.Text }
func (c *ROT13) Encrypt() { c.Data.Text = shiftAlphabet(c.Data.Text, 13) }
func (c *ROT13) Decrypt() { c.Data.Text = shiftAlphabet(c.Data.Text, 13) }
