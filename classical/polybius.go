package classical

import (
	"strings"
)

// ----- POLYBIUS -----
type KeyPolybius struct {
	Alphabet string
	Header string
}

type Polybius struct {
	Data *CipherClassicalData[KeyPolybius]
}

func (c *Polybius) GetText() string { return c.Data.Text }
func (c *Polybius) Encrypt() { c.Data.Text = encryptPolybius(c.Data.Text, c.Data.Key) }
func (c *Polybius) Decrypt() { c.Data.Text = decryptPolybius(c.Data.Text, c.Data.Key) }

func encryptPolybius(s string, key *KeyPolybius) string {
	size := len(key.Header)
	rheader := []rune(key.Header)
	result := make([]rune, len(s) * 2)

	for i, r := range s {
		rindex := strings.IndexRune(key.Alphabet, r)
		result[i * 2] = rheader[rindex / size]
		result[i * 2 + 1] = rheader[rindex % size]
	}

	return string(result)
}

func decryptPolybius(s string, key *KeyPolybius) string {
	size := len(key.Header)
	ralphabet := []rune(key.Alphabet)
	rs := []rune(s)
	result := make([]rune, len(s) / 2)

	for i := 0; i < len(s); i += 2 {
		result[i / 2] = ralphabet[strings.IndexRune(key.Header, rs[i]) * size + strings.IndexRune(key.Header, rs[i + 1])]
	}

	return string(result)
}

// ----- ADFGX -----
type KeyADFGX struct {
	Alphabet string
	Key string
}

type ADFGX struct {
	Data *CipherClassicalData[KeyADFGX]
}

func (c *ADFGX) GetText() string { return c.Data.Text }
func (c *ADFGX) Encrypt() { c.Data.Text = encryptADFGX(c.Data.Text, c.Data.Key) }
func (c *ADFGX) Decrypt() { c.Data.Text = decryptADFGX(c.Data.Text, c.Data.Key) }

func encryptADFGX(s string, key *KeyADFGX) string {
	result := encryptPolybius(s, &KeyPolybius{key.Alphabet, "ADFGX"})
	return encryptColumn(result, key.Key)
}

func decryptADFGX(s string, key *KeyADFGX) string {
	result := decryptColumn(s, key.Key)
	return decryptPolybius(result, &KeyPolybius{key.Alphabet, "ADFGX"})
}

// ----- ADFGVX -----
type KeyADFGVX struct {
	Alphabet string
	Key string
}

type ADFGVX struct {
	Data *CipherClassicalData[KeyADFGVX]
}

func (c *ADFGVX) GetText() string { return c.Data.Text }
func (c *ADFGVX) Encrypt() { c.Data.Text = encryptADFGVX(c.Data.Text, c.Data.Key) }
func (c *ADFGVX) Decrypt() { c.Data.Text = decryptADFGVX(c.Data.Text, c.Data.Key) }

func encryptADFGVX(s string, key *KeyADFGVX) string {
	result := encryptPolybius(s, &KeyPolybius{key.Alphabet, "ADFGVX"})
	return encryptColumn(result, key.Key)
}

func decryptADFGVX(s string, key *KeyADFGVX) string {
	result := decryptColumn(s, key.Key)
	return decryptPolybius(result, &KeyPolybius{key.Alphabet, "ADFGVX"})
}