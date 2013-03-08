package chaining

import (
	"crypto/cipher"
	"crypto/aes"
)

type CBC struct {
	cipher []byte
	plain []byte
	key []byte
	block cipher.Block
	kl int
}

/*
 * Creates new CBC AES encryption instance, encryption key is used to create 
 * AES block cipher
 */
func NewCBC(k []byte) *CBC {

	aes, err := aes.NewCipher(k)

	if err != nil {
		panic("AES cipher creation failed with")
	}

	cbc := &CBC{
		block: aes,
		key: k,
		kl : len(k),
	}

	return cbc
}

/*
 * Does the CBC encryption, plaintext and init vector must be provided
 */
func (c *CBC) Encrypt(p,v []byte) (result []byte) {

	mixIn := make([]byte, len(v))
	copy(mixIn, v)

	padded := false
	originalLength := len(p)

	if originalLength % c.kl != 0 {
		padded = true
		p = paddZeors(p, c.kl)
	}

	for s:=0; s < originalLength; s += c.kl {
		mixIn = c.encryptBlock(p[s:s+c.kl], mixIn)
		result = append(result, mixIn...)
	}

	if padded {
		swapLastBlock(result, c.kl)
		result = result[:originalLength]
	}

	return
}

/*
 * Encrypts single block using CBC schema
 */
func (c *CBC) encryptBlock(block, mixIn []byte) (result []byte) {
	result = make([]byte, c.kl)
	XorBlock(block, mixIn)

	c.block.Encrypt(result, block)

	return
}

/*
 * Decrpyts message text using init vector
 */
func (c *CBC) Decrypt(t, v []byte) (result []byte) {

	mixIn := make([]byte, len(v))
	copy(mixIn, v)

	padded := false
	originalLength := len(t)

	if originalLength % c.kl != 0 {

		padded = true
		//second to last block must be decrypted 
		wholeBlocks := originalLength / c.kl
		secondToLast := c.decryptBlock(t[(wholeBlocks - 1) * c.kl: wholeBlocks * c.kl], make([]byte, c.kl))
		t = paddLastBytes(t, secondToLast, c.kl)

		swapLastBlock(t, c.kl)
	}

	for s:= 0; s < len(t); s += c.kl {
		result = append(result, c.decryptBlock(t[s:s+c.kl], mixIn)...)
		mixIn = t[s:s+c.kl]
	}

	if padded {
		result = result[:originalLength]
	}

	return
}

/*
 * Decrypts single block
 */
func (c *CBC) decryptBlock(block, mixIn []byte) (result []byte){
	result = make([]byte, c.kl)
	c.block.Decrypt(result, block)
	XorBlock(result, mixIn)
	return
}
