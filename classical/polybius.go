package classical

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

func encryptPolybius(s []rune, alphabet []rune, header []rune) []rune {
	amap := buildIndexMap(alphabet)
	result := make([]rune, len(s)*2)

	for i, r := range s {
		result[i*2] = header[amap[r]/len(header)]
		result[i*2+1] = header[amap[r]%len(header)]
	}

	return result
}

func decryptPolybius(s []rune, alphabet []rune, header []rune) []rune {
	hmap := buildIndexMap(header)
	result := make([]rune, len(s)/2)

	for i := 0; i < len(s); i += 2 {
		result[i/2] = alphabet[hmap[s[i]]*len(header)+hmap[s[i+1]]]
	}

	return result
}

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

func encryptADFGX(s []rune, alphabet []rune, key []rune) []rune {
	result := encryptPolybius(s, alphabet, []rune("ADFGX"))
	return cryptColumn(result, key, true)
}

func decryptADFGX(s []rune, alphabet []rune, key []rune) []rune {
	result := cryptColumn(s, key, false)
	return decryptPolybius(result, alphabet, []rune("ADFGX"))
}

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

func encryptADFGVX(s []rune, alphabet []rune, key []rune) []rune {
	result := encryptPolybius(s, alphabet, []rune("ADFGVX"))
	return cryptColumn(result, key, true)
}

func decryptADFGVX(s []rune, alphabet []rune, key []rune) []rune {
	result := cryptColumn(s, key, false)
	return decryptPolybius(result, alphabet, []rune("ADFGVX"))
}