package cbc

import (
	"crypto/aes"
	"crypto/cipher"
	"lkr_md1/chaining"
)

type CBC struct {
	key   []byte
	block cipher.Block
	kl    int
}

/*
 * Creates new CBC AES encryption instance, encryption key is used to create 
 * AES block cipher
 */
func NewCBC(k []byte) chaining.Cipher {

	aes, err := aes.NewCipher(k)

	if err != nil {
		panic("AES cipher creation failed with")
	}

	cbc := CBC{
		block: aes,
		key:   k,
		kl:    len(k),
	}

	return &cbc
}

/*
 * Does the CBC encryption, plaintext and init vector must be provided
 */
func (c *CBC) Encrypt(p []byte) (result []byte) {

	mixIn := make([]byte, aes.BlockSize)

	padded := false
	originalLength := len(p)

	if originalLength%aes.BlockSize != 0 {
		padded = true
		p = chaining.PaddZeros(p, aes.BlockSize)
	}

	for s := 0; s < originalLength; s += aes.BlockSize {
		mixIn = c.encryptBlock(p[s:s+aes.BlockSize], mixIn)
		result = append(result, mixIn...)
	}

	if padded {
		chaining.SwapLastBlock(result, aes.BlockSize)
		result = result[:originalLength]
	}

	return
}

/*
 * Encrypts single block using CBC schema
 */
func (c *CBC) encryptBlock(block, mixIn []byte) (result []byte) {
	result = make([]byte, aes.BlockSize)
	chaining.XorBlock(block, mixIn)
	c.block.Encrypt(result, block)
	return
}

/*
 * Decrpyts message text using init vector
 */
func (c *CBC) Decrypt(t []byte) (result []byte) {

	mixIn := make([]byte, aes.BlockSize)

	padded := false
	originalLength := len(t)

	if originalLength%aes.BlockSize != 0 {

		padded = true

		//second to last block must be decrypted first
		wholeBlocks := originalLength / aes.BlockSize
		secondToLast := c.decryptBlock(t[(wholeBlocks-1)*aes.BlockSize:wholeBlocks*aes.BlockSize], mixIn)

		t = chaining.PaddLastBytes(t, secondToLast, aes.BlockSize)
		chaining.SwapLastBlock(t, aes.BlockSize)
	}

	for s := 0; s < len(t); s += aes.BlockSize {
		result = append(result, c.decryptBlock(t[s:s+aes.BlockSize], mixIn)...)
		mixIn = t[s : s+aes.BlockSize]
	}

	if padded { //trim
		result = result[:originalLength]
	}

	return
}

/*
 * Decrypts single block
 */
func (c *CBC) decryptBlock(block, mixIn []byte) (result []byte) {
	result = make([]byte, aes.BlockSize)
	c.block.Decrypt(result, block)
	chaining.XorBlock(result, mixIn)
	return
}
