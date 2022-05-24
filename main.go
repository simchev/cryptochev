package main

import (
	"cryptochev/classical"
	"fmt"
)

func main() {
	s := "WEAREDISCOVEREDFLEEATONCE"
	key1 := "CRYPTO"
	key2 := "SECRET"
	key := classical.KeyColumnDisruptedCount{CKey: key1, DKey: key2}
	c := classical.ColumnDisruptedCount{Data: &classical.CipherClassicalData[classical.KeyColumnDisruptedCount]{Text: s, Key: &key}}

	fmt.Println(classical.ToSpaced(c.Data.Text, 5))
	c.Encrypt()
	fmt.Println(classical.ToSpaced(c.Data.Text, 5))
	c.Decrypt()
	fmt.Println(classical.ToSpaced(c.Data.Text, 5))
	fmt.Println(s == c.Data.Text)
}
