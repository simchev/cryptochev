package classical

func NewKeyPolybius(alphabet []rune, header []rune) *KeyPolybius { return &KeyPolybius{Alphabet: alphabet, Header: header} }
func NewPolybius(text []rune, key *KeyPolybius) *Polybius { return &Polybius{Cipher: &CipherClassical[KeyPolybius]{Text: text, Key: key}} }

type KeyPolybius struct {
	Alphabet []rune
	Header   []rune
}

type Polybius struct { Cipher *CipherClassical[KeyPolybius] }
func (c *Polybius) GetText() []rune    { return c.Cipher.Text }
func (c *Polybius) GetErrors() []error { return c.Cipher.Errors }
func (c *Polybius) Encrypt() { c.Cipher.Text = encryptPolybius(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Header) }
func (c *Polybius) Decrypt() { c.Cipher.Text = decryptPolybius(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Header) }
func (c *Polybius) Verify() bool { return true }

func encryptPolybius(text []rune, alphabet []rune, header []rune) []rune {
	amap := buildIndexMap(alphabet)
	result := make([]rune, len(text)*2)

	for i, r := range text {
		result[i*2] = header[amap[r]/len(header)]
		result[i*2+1] = header[amap[r]%len(header)]
	}

	return result
}

func decryptPolybius(text []rune, alphabet []rune, header []rune) []rune {
	hmap := buildIndexMap(header)
	result := make([]rune, len(text)/2)

	for i := 0; i < len(text); i += 2 {
		result[i/2] = alphabet[hmap[text[i]]*len(header)+hmap[text[i+1]]]
	}

	return result
}

func NewKeyADFGX(alphabet []rune, key []rune) *KeyADFGX { return &KeyADFGX{Alphabet: alphabet, Key: key} }
func NewADFGX(text []rune, key *KeyADFGX) *ADFGX { return &ADFGX{Cipher: &CipherClassical[KeyADFGX]{Text: text, Key: key}} }

type KeyADFGX struct {
	Alphabet []rune
	Key      []rune
}

type ADFGX struct { Cipher *CipherClassical[KeyADFGX] }
func (c *ADFGX) GetText() []rune    { return c.Cipher.Text }
func (c *ADFGX) GetErrors() []error { return c.Cipher.Errors }
func (c *ADFGX) Encrypt() { c.Cipher.Text = encryptADFGX(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Key) }
func (c *ADFGX) Decrypt() { c.Cipher.Text = decryptADFGX(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Key) }
func (c *ADFGX) Verify() bool { return true }

func encryptADFGX(text []rune, alphabet []rune, key []rune) []rune {
	result := encryptPolybius(text, alphabet, []rune("ADFGX"))
	return cryptColumn(result, key, true)
}

func decryptADFGX(text []rune, alphabet []rune, key []rune) []rune {
	result := cryptColumn(text, key, false)
	return decryptPolybius(result, alphabet, []rune("ADFGX"))
}

func NewKeyADFGVX(alphabet []rune, key []rune) *KeyADFGVX { return &KeyADFGVX{Alphabet: alphabet, Key: key} }
func NewADFGVX(text []rune, key *KeyADFGVX) *ADFGVX { return &ADFGVX{Cipher: &CipherClassical[KeyADFGVX]{Text: text, Key: key}} }

type KeyADFGVX struct {
	Alphabet []rune
	Key      []rune
}

type ADFGVX struct { Cipher *CipherClassical[KeyADFGVX] }
func (c *ADFGVX) GetText() []rune    { return c.Cipher.Text }
func (c *ADFGVX) GetErrors() []error { return c.Cipher.Errors }
func (c *ADFGVX) Encrypt() {  c.Cipher.Text = encryptADFGVX(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Key) }
func (c *ADFGVX) Decrypt() { c.Cipher.Text = decryptADFGVX(c.Cipher.Text, c.Cipher.Key.Alphabet, c.Cipher.Key.Key) }
func (c *ADFGVX) Verify() bool { return true }

func encryptADFGVX(text []rune, alphabet []rune, key []rune) []rune {
	result := encryptPolybius(text, alphabet, []rune("ADFGVX"))
	return cryptColumn(result, key, true)
}

func decryptADFGVX(text []rune, alphabet []rune, key []rune) []rune {
	result := cryptColumn(text, key, false)
	return decryptPolybius(result, alphabet, []rune("ADFGVX"))
}