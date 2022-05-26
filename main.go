package main

import (
	"cryptochev/classical"
	"fmt"
)

func main() {
	s := "WEATTACKAT1200AM"
	key1 := classical.AlphabetL36
	key2 := "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもん"
	key := classical.KeySubstitute{Alphabet: key1, SAlphabet: key2}
	c := classical.Substitute{Data: &classical.CipherClassicalData[classical.KeySubstitute]{Text: s, Key: &key}}

	fmt.Println(classical.ToSpaced(c.Data.Text, 5))
	c.Encrypt()
	fmt.Println(classical.ToSpaced(c.Data.Text, 5))
	c.Decrypt()
	fmt.Println(classical.ToSpaced(c.Data.Text, 5))
	fmt.Println(s == c.Data.Text)
}
