package main

import (
	"cryptochev/classical"
	"fmt"
)

func main() {
	s := "WEAREDISCOVEREDFLEEATONCE"
	keycode := "TOMATO"
	key := classical.KeyColumn(keycode)
	c := classical.Column{Data: &classical.CipherClassicalData[classical.KeyColumn]{Text: s, Key: &key}}

	fmt.Println(classical.ToSpaced(c.Data.Text, 5))
	c.Encrypt()
	fmt.Println(classical.ToSpaced(c.Data.Text, 5))
	c.Decrypt()
	fmt.Println(classical.ToSpaced(c.Data.Text, 5))
	fmt.Println(s == c.Data.Text)
}
