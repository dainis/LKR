package chaining

type Cipher interface {
	Encrypt(plain []byte) []byte
	Decrypt(cipherText []byte) []byte
}
