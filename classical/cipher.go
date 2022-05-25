package classical

type CipherClassicalData[K CipherClassicalKey] struct {
	Text string
	Key  *K
}

type CipherClassical interface {
	GetText() string
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
		KeyVigenere
}