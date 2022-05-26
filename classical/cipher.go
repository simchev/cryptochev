package classical

type CipherClassicalData[K CipherClassicalKey] struct {
	Text []rune
	Key  *K
}

type CipherClassical interface {
	GetText() []rune
	Encrypt()
	Decrypt()
}

type CipherClassicalKey interface {
	KeyADFGVX |
		KeyADFGX |
		KeyColumn |
		KeyPolybius |
		KeyRoute |
		KeyShift |
		KeyROT13 |
		KeyZigzag |
		KeyScytale |
		KeyMyszkowski |
		KeyCaesar |
		KeyMagnet |
		KeyElastic |
		KeyReverse |
		KeyColumnDCount |
		KeyColumnDLine |
		KeyVigenere |
		KeySubstitute |
		KeyAutokey
}