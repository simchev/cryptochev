package main

import (
	"cryptochev/classical"
	"fmt"
)

func main() {
	s := "ATTACKATDAWN"
	key1 := classical.AlphabetL
	key2 := "QUEENLY"
	key := classical.KeyAutokey{Alphabet: []rune(key1), Primer: []rune(key2)}
	c := classical.Autokey{Data: &classical.CipherClassicalData[classical.KeyAutokey]{Text: []rune(s), Key: &key}}

	fmt.Println(classical.ToSpaced(string(c.Data.Text), 5))
	c.Encrypt()
	fmt.Println(classical.ToSpaced(string(c.Data.Text), 5))
	c.Decrypt()
	fmt.Println(classical.ToSpaced(string(c.Data.Text), 5))
	fmt.Println(s == string(c.Data.Text))
}
