package ofb

import (
	"crypto/aes"
	"crypto/cipher"
	"lkr_md1/chaining"
)

type OFB struct {
	key   []byte
	block cipher.Block
	kl    int
}

func NewOFB(key []byte) chaining.Cipher {

	aes, err := aes.NewCipher(key)

	if err != nil {
		panic(err)
	}

	ofb := OFB{
		block: aes,
		key:   key,
		kl:    len(key),
	}

	return &ofb
}

//Encrypts plaintext using ofb chaining method
func (o *OFB) Encrypt(p []byte) []byte {
	p = chaining.PadMissingLenth(p, aes.BlockSize)
	initVector := chaining.GetRandomBytes(aes.BlockSize)
	return append(initVector, o.performOFB(p, initVector)...)
}

//Decrypts using ofb chaining method, initialization vector is as the first
//block of the cipher text
func (o *OFB) Decrypt(ct []byte) []byte {
	initVector := ct[:aes.BlockSize]
	result := o.performOFB(ct[aes.BlockSize:], initVector)
	return chaining.RemovePad(result)
}

//Does the actual ofb, encrypt and decrypt are exacly the same
func (o *OFB) performOFB(t, mixIn []byte) (result []byte) {

	var ct []byte

	totalLenth := len(t)

	for s := 0; s < totalLenth; s += aes.BlockSize {
		ct, mixIn = o.doBlock(t[s:s+aes.BlockSize], mixIn)
		result = append(result, ct...)
	}

	return
}

//Encrypts one block using ofb
func (o *OFB) doBlock(b, mixIn []byte) (result, nextMix []byte) {
	nextMix = make([]byte, aes.BlockSize)
	o.block.Encrypt(nextMix, mixIn)

	result = make([]byte, aes.BlockSize)
	copy(result, b)

	chaining.XorBlock(result, nextMix)

	return
}