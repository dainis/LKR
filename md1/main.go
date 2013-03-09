package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"lkr_md1/chaining"
	"lkr_md1/chaining/cbc"
)

var mode = flag.String("m", "e", "e - to encrypt, d - to crypt")
var inputFile = flag.String("f", "", "Input file")
var keyFile = flag.String("k", "", "Encryption/decryption key file")
var vectorFile = flag.String("v", "", "Initialization vector file")
var outputFile = flag.String("o", "", "Output file")

func main() {
	flag.Parse()
	if *mode != "e" && *mode != "d" {
		flag.PrintDefaults()
		panic("Invalid mode " + *mode)
	}

	if *inputFile == "" {
		flag.PrintDefaults()
		panic("No input file specified")
	}

	if *keyFile == "" {
		flag.PrintDefaults()
		panic("No key file specified")
	}

	if *vectorFile == "" {
		flag.PrintDefaults()
		panic("No vector file specified")
	}

	key, err := ioutil.ReadFile(*keyFile)

	if err != nil {
		flag.PrintDefaults()
		panic("Couldnt read key file")
	}

	input, err := ioutil.ReadFile(*inputFile)

	if err != nil {
		flag.PrintDefaults()
		panic("Couldnt read input file")
	}

	cbc := cbc.NewCBC(key)

	if *mode == "e" {
		doCBCEncrypt(input, cbc)
	} else {
		doCBCDecrypt(input, cbc)
	}
}

func doCBCEncrypt(input []byte, cbc *cbc.CBC) {

	initVector := chaining.GetInitVector(cbc.GetBlockSize())
	fmt.Printf("plain length \t: %d\n", len(input))

	ct := cbc.Encrypt(input, initVector)

	fmt.Printf("encrpyted size \t: %d\n", len(ct))

	err := ioutil.WriteFile(*outputFile, ct, 0644)
	if err != nil {
		panic("Failed to write output to file")
	}

	err = ioutil.WriteFile(*vectorFile, initVector, 0644)
	if err != nil {
		panic("Failed to write initialization vector file")
	}
}

func doCBCDecrypt(input []byte, cbc *cbc.CBC) {
	initVector, err := ioutil.ReadFile(*vectorFile)
	if err != nil {
		panic("Couldnt read initialization vector")
	}

	fmt.Printf("encrpyted size \t:%d\n", len(input))

	pt := cbc.Decrypt(input, initVector)

	fmt.Printf("decrypted size \t:%d\n", len(pt))
	err = ioutil.WriteFile(*outputFile, pt, 0644)
	if err != nil {
		panic("Couldnt write decrypted file")
	}
}
