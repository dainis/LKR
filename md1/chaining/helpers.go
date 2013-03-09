package chaining

import (
	"crypto/rand"
	"io"
)

/*
 * Adds trailing zeros so that block size would be rounded to up to exact required
 * block size
 */
func PaddZeros(t []byte, size int) []byte {
	offBy := size - (len(t) % size)
	temp := make([]byte, offBy)
	t = append(t, temp...)
	return t
}

/*
 * Swaps last two block of the given size
 */
func SwapLastBlock(block []byte, size int) {
	l := len(block)
	for i := 0; i < size; i++ {
		temp := block[l-2*size+i]
		block[l-2*size+i] = block[l-size+i]
		block[l-size+i] = temp
	}
}

/*
 * Pads input with last bytes of other message to make up missing block size
 */
func PaddLastBytes(t, f []byte, size int) []byte {
	l := len(t)
	t = append(t, f[l%size:len(f)]...)
	return t
}

/*
 * Creates byte array which will serve as initialization vector
 */
func GetInitVector(size int) (vector []byte) {
	vector = make([]byte, size)
	_, err := io.ReadFull(rand.Reader, vector)
	if err != nil {
		panic("ERROR while creating init vector")
	}
	return
}

/*
 * Does xor for two byte blocks
 */
func XorBlock(b, c []byte) {
	for i := range c {
		b[i] ^= c[i]
	}
}
