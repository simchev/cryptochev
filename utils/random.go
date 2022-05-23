package utils

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	math_rand "math/rand"
)

// https://stackoverflow.com/questions/12321133/how-to-properly-seed-random-number-generator
func SeedRand() int64 {
    var b [8]byte
    _, err := crypto_rand.Read(b[:])

    if err != nil {
        panic("Cannot seed math/rand package with cryptographically secure random number generator")
    }

    seed := int64(binary.LittleEndian.Uint64(b[:]))
    math_rand.Seed(seed)

    return seed
}