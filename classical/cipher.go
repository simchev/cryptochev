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

type KeyNone struct{}

type CipherClassicalKey interface {
	KeyNone |
		KeyADFGVX |
		KeyADFGX |
		KeyColumn |
		KeyPolybius |
		KeyRoute |
		KeyShift |
		KeyZigzag |
		KeyScytale |
		KeyMyszkowski |
		KeyCaesar |
		KeyColumnDCount |
		KeyColumnDLine |
		KeyVigenere |
		KeySubstitute |
		KeyAutokey |
		KeyPlayfair |
		KeyAffine |
		KeyAtbash |
		KeyBeaufort |
		KeyShiftAlphabet
}