package main

import (
	"cryptochev/classical"
	"fmt"
)

func main() {
	s := "WEATTACKAT1200AM"
	key1 := classical.AlphabetL36
	key2 := "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもん"
	key := classical.KeySubstitute{Alphabet: []rune(key1), SAlphabet: []rune(key2)}
	c := classical.Substitute{Data: &classical.CipherClassicalData[classical.KeySubstitute]{Text: []rune(s), Key: &key}}

	fmt.Println(classical.ToSpaced(string(c.Data.Text), 5))
	c.Encrypt()
	fmt.Println(classical.ToSpaced(string(c.Data.Text), 5))
	c.Decrypt()
	fmt.Println(classical.ToSpaced(string(c.Data.Text), 5))
	fmt.Println(s == string(c.Data.Text))
}
