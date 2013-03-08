package main
import (
	"lkr_md1/chaining"
	"fmt"
	"io/ioutil"
)

func main(){
	key, err := ioutil.ReadFile("key.txt")

	if err != nil {
		panic("Couldnt read key file")
	}

	c := chaining.NewCBC(key)
	plain, err := ioutil.ReadFile("plain.txt")
	initVector := chaining.GetInitVector(16)

	fmt.Printf("plain length\t: %d\n", len(plain))

	ct := c.Encrypt(plain, initVector)

	fmt.Printf("Enc len \t: %d\n", len(ct))
	ioutil.WriteFile("vect.txt", initVector, 0644)
	ioutil.WriteFile("c.txt", ct, 0644)

	dt := c.Decrypt(ct, initVector)
	fmt.Printf("Dec len \t: %d\n", len(dt))

	ioutil.WriteFile("res.txt", dt, 0644)
}
