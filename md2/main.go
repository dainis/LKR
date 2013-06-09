package main

import (
	"flag"
	"fmt"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/sha1"
	"math/big"
	"encoding/pem"
	"os"
	"io/ioutil"
	"log"
	"time"
)

var (
	action = flag.String("a", "", "Action : p - create x509 pair, v - validate pair, e - encrypt, d - decrypt")
	keyFile = flag.String("k", "", "Key file")
	certFile = flag.String("c", "", "Certificate file")
	inputFile = flag.String("i", "", "Input file")
	outputFile = flag.String("o", "", "Output file")
	commonName = flag.String("n", "", "Common name for certificate")
)

func validateKeyFile() {
	if(*keyFile == "") {
		exitWithMessage("no key file specified")
	}
}

func validateCertFile() {
	if(*certFile == "") {
		exitWithMessage("no certificate file specified")
	}
}

func validateInputFile() {
	if(*inputFile == "") {
		exitWithMessage("no input file specified")
	}
}

func validateOutputFile() {
	if(*outputFile == "") {
		exitWithMessage("no output file specified")
	}
}

func validateCommonName() {
	if(*commonName == "") {
		exitWithMessage("no common name specified")
	}
}

func exitWithMessage(msg string) {
	flag.PrintDefaults()
	fmt.Print("\n" + msg + "\n\n")
	os.Exit(1)
}

func handleError(err error, where string) {
	if(err != nil) {
		log.Fatalf("Error %s : %s", where, err);
	}
}

func validateAndCreatePair() {
	validateCertFile()
	validateKeyFile()
	validateCommonName();

	create(*certFile, *keyFile, *commonName)
}

func validateAndVerify() {
	validateCertFile()

	verify(*certFile)
}

func validaAndEncrypt() {
	validateCertFile()
	validateInputFile()
	validateOutputFile()

	encrypt(*certFile, *inputFile, *outputFile)
}

func validateAndDecrypt() {
	validateKeyFile()
	validateInputFile()
	validateKeyFile()

	decrypt(*keyFile, *inputFile, *outputFile)
}

func main() {
	flag.Parse()

	switch *action {
		default  : exitWithMessage("invalid action " + *action)
		case "p" : validateAndCreatePair()
		case "v" : validateAndVerify()
		case "e" : validaAndEncrypt()
		case "d" : validateAndDecrypt()

	}
}

//Encrypts given file with using given certificate, output is writen to
//specified output file
func encrypt(certPath, inputFile, outputFile string) {
	cert := readAndCreateCert(certPath)

	input, err := ioutil.ReadFile(inputFile)

	handleError(err, "reading input file")

	out, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, cert.PublicKey.(*rsa.PublicKey), input, []byte(outputFile))

	handleError(err, "encrypting")

	err = ioutil.WriteFile(outputFile, out, 0644)

	handleError(err, "writing encrypted file")

	log.Printf("Encrpyted %s => %s", inputFile, outputFile)
}

//Decryptes input file using specified private key, ouput is written to
//output file
func decrypt(keyFile, inputFile, outputFile string) {
	rawKey, err := ioutil.ReadFile(keyFile)

	handleError(err, "reading key file")

	rawBlock, _ := pem.Decode(rawKey)

	key, err := x509.ParsePKCS1PrivateKey(rawBlock.Bytes)

	handleError(err, "parsing private key")

	input, err := ioutil.ReadFile(inputFile)

	handleError(err, "reading input")

	output, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, key, input, []byte(inputFile))

	handleError(err, "decrypting message")

	err = ioutil.WriteFile(outputFile, output, 0644)

	handleError(err, "writing output")

	log.Printf("decrypted %s => %s", inputFile, outputFile)
}

//Just a helper function for reading certiface from file system and creating
//certiface object
func readAndCreateCert(certPath string) (cert *x509.Certificate) {
	rawCert, err := ioutil.ReadFile(certPath)

	handleError(err, "reading certifitcate")

	certBlock, _ := pem.Decode(rawCert)

	cert, err = x509.ParseCertificate(certBlock.Bytes);

	handleError(err, "parsing certificate")

	return
}

//Verifies that certificate file is correct x509 certificate and that is
//self signed certificate
func verify(certPath string) {
	cert := readAndCreateCert(certPath)

	pool := x509.NewCertPool() //add or certificate to certificate pool so that we can check that it is self signed
	pool.AddCert(cert)
	opts := x509.VerifyOptions{Roots : pool}

	_, err := cert.Verify(opts)

	if(err != nil) {
		fmt.Printf("\n\nCertificate isnt valid because of : '%s' \n\n", err)
	} else {
		fmt.Printf("\n\nCertifiacte is valid and is issued to '%s' \n\n", cert.Subject.CommonName)
	}
}

//Creates self signed certificate and private key pair with given common name
//and writes them back to files system
func create(certPath, keyPath, commonName string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	handleError(err, "generating rsa key")

	now := time.Now()

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"LU"},
		},
		NotBefore: now.Add(-5 * time.Minute).UTC(),
		NotAfter:  now.AddDate(1, 0, 0).UTC(), // valid for 1 year.
		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA : true,
		BasicConstraintsValid : true,
	}

	//using same certificate object to sign created certificate results in self signed certificate
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	handleError(err, "creating certificate")

	certOut, err := os.Create(certPath)
	handleError(err, "opening cert file")

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	certOut.Close()

	log.Printf("certificate written %s\n", certPath)

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) //RW for owner only
	handleError(err, "opening key file")

	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	log.Printf("key written %s\n", keyPath)
}