package classical

type CipherClassical[K CipherClassicalKey] struct {
	Text   []rune
	Errors []error
	Key    *K
}

type ICipherClassical interface {
	GetText() []rune
	GetErrors() []error
	Encrypt()
	Decrypt()
	Verify() bool
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
		KeyAutokey |
		KeyPlayfair
}