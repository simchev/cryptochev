package main

import (
	"cryptochev/classical"
	"fmt"
)

func main() {
	s := "WEAREDISCOVEREDFLEEATONCE"
	key1 := "CRYPTO"
	key2 := "SECRET"
	key := classical.KeyColumnDCount{CKey: key1, DKey: key2}
	c := classical.ColumnDCount{Data: &classical.CipherClassicalData[classical.KeyColumnDCount]{Text: s, Key: &key}}

	fmt.Println(classical.ToSpaced(c.Data.Text, 5))
	c.Encrypt()
	fmt.Println(classical.ToSpaced(c.Data.Text, 5))
	c.Decrypt()
	fmt.Println(classical.ToSpaced(c.Data.Text, 5))
	fmt.Println(s == c.Data.Text)
}
