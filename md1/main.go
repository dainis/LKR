package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"lkr_md1/chaining"
	"lkr_md1/chaining/cbc"
	"lkr_md1/chaining/ofb"
	"os"
)

var action = flag.String("a", "e", "Action e - to encrypt, d - to crypt")
var inputFile = flag.String("f", "", "Input file")
var keyFile = flag.String("k", "", "Encryption/decryption key file")
var vectorFile = flag.String("v", "", "Initialization vector file")
var outputFile = flag.String("o", "", "Output file")
var cipherMode = flag.String("m", "cbc", "CBC or OFB")
var keyGenMode = flag.Int("g", 0, "if non null value then generate only generate key file for given size")

func exitWithMessage(msg string) {
	flag.PrintDefaults()
	fmt.Print("\n"+msg+"\n\n")
	os.Exit(1)
}

func main() {
	flag.Parse()
	if *keyGenMode != 0 {
		doKeyGeneration();
		return
	}

	if *action != "e" && *action != "d" {
		exitWithMessage("Invalid action")
	}

	if *cipherMode != "cbc" && *cipherMode != "ofb" {
		exitWithMessage("Invalid cipher mode")
	}

	if *inputFile == "" {
		exitWithMessage("No input file specified")
	}

	if *keyFile == "" {
		exitWithMessage("No key file specified")
	}

	if *vectorFile == "" {
		exitWithMessage("No vector file specified")
	}

	key, err := ioutil.ReadFile(*keyFile)

	if err != nil {
		exitWithMessage("Couldn't read key file")
	}

	input, err := ioutil.ReadFile(*inputFile)

	if err != nil {
		exitWithMessage("Couldn't read input file")
	}

	var cipher chaining.Cipher

	if *cipherMode == "cbc" {
		cipher = cbc.NewCBC(key)
	} else {
		cipher = ofb.NewOFB(key)
	}

	if *action == "e" {
		doEncrypt(input, cipher)
	} else {
		doDecrypt(input, cipher)
	}
}

func doKeyGeneration() {
	err := ioutil.WriteFile(*outputFile, chaining.GetRandomBytes(*keyGenMode), 0644)
	if err != nil {
		panic("Couldn't write key file")
	}
	os.Exit(0)
}

func doEncrypt(input []byte, cipher chaining.Cipher) {

	initVector := chaining.GetRandomBytes(cipher.GetBlockSize())
	fmt.Printf("plain length \t: %d\n", len(input))

	ct := cipher.Encrypt(input, initVector)

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

func doDecrypt(input []byte, cipher chaining.Cipher) {

	initVector, err := ioutil.ReadFile(*vectorFile)

	if err != nil {
		panic("Couldnt read initialization vector")
	}

	fmt.Printf("encrpyted size \t:%d\n", len(input))

	pt := cipher.Decrypt(input, initVector)

	fmt.Printf("decrypted size \t:%d\n", len(pt))
	err = ioutil.WriteFile(*outputFile, pt, 0644)

	if err != nil {
		panic("Couldnt write decrypted file")
	}
}
