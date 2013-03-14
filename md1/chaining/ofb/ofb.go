package ofb
import (
	"crypto/aes"
	"crypto/cipher"
	"lkr_md1/chaining"
)

type OFB struct {
	key []byte
	block cipher.Block
	kl int
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

func (o *OFB) Encrypt(p, v []byte) []byte {
	p = chaining.PadMissingLenth(p, o.kl)

	return o.performOFB(p, v)
}

func (o *OFB) Decrypt(ct, v []byte) []byte {
	result := o.performOFB(ct, v)

	return chaining.RemovePad(result)
}

func (o *OFB) performOFB(t, v []byte) (result []byte) {

	var ct []byte

	mixIn := make([]byte, o.kl)
	copy(mixIn, v)

	totalLenth := len(t)

	for s:= 0; s < totalLenth; s+=o.kl {
		ct, mixIn = o.doBlock(t[s : s  * o.kl], mixIn)
		result = append(result, ct...)
	}

	return
}

func (o *OFB) doBlock(b, mixIn []byte) (result, nextMix []byte) {

	nextMix = make([]byte, o.kl)
	o.block.Encrypt(nextMix, mixIn)

	result = make([]byte, o.kl)
	copy(result, b)

	chaining.XorBlock(result, nextMix)

	return
}

func (o *OFB) GetBlockSize() int {
	return o.kl
}
