package classical

import "unicode"

func NewKeyVigenere(alphabet []rune, key []rune) *KeyVigenere { return &KeyVigenere{Alphabet: alphabet, Key: key} }
func NewVigenere(text []rune, key *KeyVigenere) *Vigenere { return &Vigenere{Cipher: &CipherClassical[KeyVigenere]{Text: text, Key: key}} }

type KeyVigenere struct {
	Alphabet []rune
	Key []rune
}

type Vigenere struct { Cipher *CipherClassical[KeyVigenere] }
func (c *Vigenere) GetText() []rune { return c.Cipher.Text }
func (c *Vigenere) GetErrors() []error { return c.Cipher.Errors }
func (c *Vigenere) Encrypt() { c.Cipher.Text = cryptVigenere(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Key, true) }
func (c *Vigenere) Decrypt() { c.Cipher.Text = cryptVigenere(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Key, false) }
func (c *Vigenere) Verify() bool { return true }

func cryptVigenere(text []rune, alphabet []rune, key []rune, encrypt bool) []rune {
	if len(key) == 0 {
		key = alphabet
	}

	result := make([]rune, len(text))
	amap := buildIndexMap(alphabet)
	
	for i, r := range text {
		if encrypt {
			result[i] = alphabet[(amap[r] + amap[key[i % len(key)]]) % len(alphabet)]
		} else {
			result[i] = alphabet[(amap[r] - amap[key[i % len(key)]] + len(alphabet)) % len(alphabet)]
		}
	}

	return result
}

func NewVigenereBeaufort(text []rune, key *KeyVigenere) *VigenereBeaufort { return &VigenereBeaufort{Cipher: &CipherClassical[KeyVigenere]{Text: text, Key: key}} }

type VigenereBeaufort struct { Cipher *CipherClassical[KeyVigenere] }
func (c *VigenereBeaufort) GetText() []rune { return c.Cipher.Text }
func (c *VigenereBeaufort) GetErrors() []error { return c.Cipher.Errors }
func (c *VigenereBeaufort) Encrypt() { c.Cipher.Text = cryptVigenere(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Key, false) }
func (c *VigenereBeaufort) Decrypt() { c.Cipher.Text = cryptVigenere(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Key, true) }
func (c *VigenereBeaufort) Verify() bool { return true }

func gronsfeldToVigenereKey(alphabet []rune, key []rune) []rune {
	keyv := make([]rune, 0, len(key))

	for _, r := range key {
		if unicode.IsDigit(r) {
			keyv = append(keyv, alphabet[r - '0'])
		}
	}

	return keyv
}

func NewVigenereGronsfeld(text []rune, key *KeyVigenere) *VigenereGronsfeld { return &VigenereGronsfeld{Cipher: &CipherClassical[KeyVigenere]{Text: text, Key: key}} }

type VigenereGronsfeld struct { Cipher *CipherClassical[KeyVigenere] }
func (c *VigenereGronsfeld) GetText() []rune { return c.Cipher.Text }
func (c *VigenereGronsfeld) GetErrors() []error { return c.Cipher.Errors }
func (c *VigenereGronsfeld) Encrypt() { c.Cipher.Text = cryptVigenere(c.Cipher.Text, c.Cipher.Key.Alphabet, gronsfeldToVigenereKey(c.Cipher.Key.Alphabet, c.Cipher.Key.Key), true) }
func (c *VigenereGronsfeld) Decrypt() { c.Cipher.Text = cryptVigenere(c.Cipher.Text, c.Cipher.Key.Alphabet, gronsfeldToVigenereKey(c.Cipher.Key.Alphabet, c.Cipher.Key.Key), false) }
func (c *VigenereGronsfeld) Verify() bool { return true }

func NewKeyAutokey(alphabet []rune, primer []rune) *KeyAutokey { return &KeyAutokey{Alphabet: alphabet, Primer: primer} }
func NewAutokey(text []rune, key *KeyAutokey) *Autokey { return &Autokey{Cipher: &CipherClassical[KeyAutokey]{Text: text, Key: key}} }

type KeyAutokey struct {
	Alphabet []rune
	Primer []rune
}

type Autokey struct { Cipher *CipherClassical[KeyAutokey] }
func (c *Autokey) GetText() []rune { return c.Cipher.Text }
func (c *Autokey) GetErrors() []error { return c.Cipher.Errors }
func (c *Autokey) Encrypt() { c.Cipher.Text = cryptVigenere(c.Cipher.Text, c.Cipher.Key.Alphabet, append(c.Cipher.Key.Primer, c.Cipher.Text...), true) }
func (c *Autokey) Decrypt() { c.Cipher.Text = decryptAutokey(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Primer) }
func (c *Autokey) Verify() bool { return true }

func decryptAutokey(text []rune, alphabet []rune, primer []rune) []rune {
	result := make([]rune, len(text))
	key := make([]rune, 0, len(text) + len(primer))
	key = append(key, primer...)
	amap := buildIndexMap(alphabet)
	
	for i, r := range text {
		result[i] = alphabet[(amap[r] - amap[key[i]] + len(alphabet)) % len(alphabet)]
		key = append(key, result[i])
	}

	return result
}

func NewKeyBeaufort(alphabet []rune, key []rune) *KeyBeaufort { return &KeyBeaufort{Alphabet: alphabet, Key: key} }
func NewBeaufort(text []rune, key *KeyBeaufort) *Beaufort { return &Beaufort{Cipher: &CipherClassical[KeyBeaufort]{Text: text, Key: key}} }

type KeyBeaufort struct {
	Alphabet []rune
	Key []rune
}

type Beaufort struct { Cipher *CipherClassical[KeyBeaufort] }
func (c *Beaufort) GetText() []rune { return c.Cipher.Text }
func (c *Beaufort) GetErrors() []error { return c.Cipher.Errors }
func (c *Beaufort) Encrypt() { c.Cipher.Text = cryptBeaufort(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Key) }
func (c *Beaufort) Decrypt() { c.Cipher.Text = cryptBeaufort(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Key) }
func (c *Beaufort) Verify() bool { return true }

func cryptBeaufort(text []rune, alphabet []rune, key []rune) []rune {
	if len(key) == 0 {
		key = alphabet
	}

	result := make([]rune, len(text))
	amap := buildIndexMap(alphabet)
	
	for i, r := range text {
		result[i] = alphabet[(amap[key[i % len(key)]] - amap[r] + len(alphabet)) % len(alphabet)]
	}

	return result
}