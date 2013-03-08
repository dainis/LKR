package chaining

/*
 * Adds trailing zeros so that block size would be rounded to up to exact required
 * block size
 */
func paddZeors(t []byte, size int) []byte{
	offBy := size - (len(t) % size)
	temp := make([]byte, offBy)
	t = append(t, temp...)
	return t
}

/*
 * Swaps last two block of the given size
 */
func swapLastBlock(block []byte, size int) {
	l := len(block)
	for i := 0; i < size; i++ {
		temp := block[l - 2 * size + i]
		block[l - 2 * size + i] = block[l - size + i]
		block[l - size + i] = temp
	}
}

/*
 * Pads input with last bytes of other message to make up missing block size
 */
func paddLastBytes(t, f []byte, size int) []byte{
	l := len(t)
	t = append(t, f[l %size: len(f)]...)
	return t
}
