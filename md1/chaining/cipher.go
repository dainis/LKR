package chaining

type Cipher interface {
	Encrypt(plain, initVect []byte) []byte
	Decrypt(cipherText, initVect []byte) []byte
	GetBlockSize() int
}
