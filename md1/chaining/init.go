package chaining

import (
	"crypto/rand"
	"io"
)

func GetInitVector(size int) (vector []byte) {
	vector = make([]byte, size)
	_, err := io.ReadFull(rand.Reader, vector)
	if err != nil {
		panic("ERROR while creating init vector")
	}
	return
}

func XorBlock(b, c []byte) {
	for i := range c {
		b[i] ^= c[i]
	}
}
