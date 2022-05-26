package classical

type KeyPolybius struct {
	Alphabet []rune
	Header   []rune
}

type Polybius struct {
	Data *CipherClassicalData[KeyPolybius]
}

func (c *Polybius) GetText() []rune { return c.Data.Text }
func (c *Polybius) Encrypt() {
	c.Data.Text = encryptPolybius(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Header)
}
func (c *Polybius) Decrypt() {
	c.Data.Text = decryptPolybius(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Header)
}

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

type ADFGX struct {
	Data *CipherClassicalData[KeyADFGX]
}

func (c *ADFGX) GetText() []rune { return c.Data.Text }
func (c *ADFGX) Encrypt() {
	c.Data.Text = encryptADFGX(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Key)
}
func (c *ADFGX) Decrypt() {
	c.Data.Text = decryptADFGX(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Key)
}

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

type ADFGVX struct {
	Data *CipherClassicalData[KeyADFGVX]
}

func (c *ADFGVX) GetText() []rune { return c.Data.Text }
func (c *ADFGVX) Encrypt() {
	c.Data.Text = encryptADFGVX(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Key)
}
func (c *ADFGVX) Decrypt() {
	c.Data.Text = decryptADFGVX(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Key)
}

func encryptADFGVX(s []rune, alphabet []rune, key []rune) []rune {
	result := encryptPolybius(s, alphabet, []rune("ADFGVX"))
	return cryptColumn(result, key, true)
}

func decryptADFGVX(s []rune, alphabet []rune, key []rune) []rune {
	result := cryptColumn(s, key, false)
	return decryptPolybius(result, alphabet, []rune("ADFGVX"))
}