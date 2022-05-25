package classical

type KeyPolybius struct {
	Alphabet string
	Header   string
}

type Polybius struct {
	Data *CipherClassicalData[KeyPolybius]
}

func (c *Polybius) GetText() string { return c.Data.Text }
func (c *Polybius) Encrypt() {
	c.Data.Text = encryptPolybius(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Header)
}
func (c *Polybius) Decrypt() {
	c.Data.Text = decryptPolybius(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Header)
}

func encryptPolybius(s string, alphabet string, header string) string {
	rheader := []rune(header)
	amap := buildIndexMap(alphabet)
	result := make([]rune, len(s)*2)

	for i, r := range s {
		result[i*2] = rheader[amap[r]/len(header)]
		result[i*2+1] = rheader[amap[r]%len(header)]
	}

	return string(result)
}

func decryptPolybius(s string, alphabet string, header string) string {
	ralphabet := []rune(alphabet)
	hmap := buildIndexMap(header)
	rs := []rune(s)
	result := make([]rune, len(s)/2)

	for i := 0; i < len(s); i += 2 {
		result[i/2] = ralphabet[hmap[rs[i]]*len(header)+hmap[rs[i+1]]]
	}

	return string(result)
}

type KeyADFGX struct {
	Alphabet string
	Key      string
}

type ADFGX struct {
	Data *CipherClassicalData[KeyADFGX]
}

func (c *ADFGX) GetText() string { return c.Data.Text }
func (c *ADFGX) Encrypt() {
	c.Data.Text = encryptADFGX(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Key)
}
func (c *ADFGX) Decrypt() {
	c.Data.Text = decryptADFGX(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Key)
}

func encryptADFGX(s string, alphabet string, key string) string {
	result := encryptPolybius(s, alphabet, "ADFGX")
	return encryptColumn(result, key)
}

func decryptADFGX(s string, alphabet string, key string) string {
	result := decryptColumn(s, key)
	return decryptPolybius(result, alphabet, "ADFGX")
}

type KeyADFGVX struct {
	Alphabet string
	Key      string
}

type ADFGVX struct {
	Data *CipherClassicalData[KeyADFGVX]
}

func (c *ADFGVX) GetText() string { return c.Data.Text }
func (c *ADFGVX) Encrypt() {
	c.Data.Text = encryptADFGVX(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Key)
}
func (c *ADFGVX) Decrypt() {
	c.Data.Text = decryptADFGVX(c.Data.Text, c.Data.Key.Alphabet, c.Data.Key.Key)
}

func encryptADFGVX(s string, alphabet string, key string) string {
	result := encryptPolybius(s, alphabet, "ADFGVX")
	return encryptColumn(result, key)
}

func decryptADFGVX(s string, alphabet string, key string) string {
	result := decryptColumn(s, key)
	return decryptPolybius(result, alphabet, "ADFGVX")
}