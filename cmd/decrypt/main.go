package main

import (
	"flag"
	"io/ioutil"
	"os"

	"github.com/keybase/go-triplesec"

	"github.com/sirupsen/logrus"
)

func main() {

	/* Output tool start log */
	logrus.Printf("Starting the eldim decryption tool...")

	/* Command line flags with all needed data */
	inputFile := flag.String("in", "input.dat", "The encrypted file to decrypt.")
	outputFile := flag.String("out", "output.dat", "The file to save the decrypted data.")
	encryptionKey := flag.String("key", "Insecure", "The encryption password to decrypt the data.")

	flag.Parse()

	/* Print input and output file to log for documentation purposes */
	logrus.Printf("Started with input file \"%s\" and output file \"%s\"", *inputFile, *outputFile)

	/* Delete any file that exists in the outputFile */
	os.Remove(*outputFile)

	/* Read the encrypted file to RAM */
	logrus.Printf("Reading encrypted file to memory...")
	encData, err := ioutil.ReadFile(*inputFile)
	if err != nil {
		logrus.Fatalf("Failed to read input file: %v", err)
	}
	logrus.Printf("File in memory. Size: %d bytes", len(encData))

	/* Create an output file */
	f, err := os.Create(*outputFile)
	if err != nil {
		logrus.Fatalf("Failed to create output file: %v", err)
	}

	logrus.Printf("Decrypting data...")

	/* Create a new TripleSec cipher */
	cipher, err := triplesec.NewCipher([]byte(*encryptionKey), nil)
	if err != nil {
		logrus.Fatalf("Failed to initialize the cryptographic engine: %v", err)
	}

	/* Decrypt the data in memory */
	dec, err := cipher.Decrypt(encData)
	if err != nil {
		logrus.Fatalf("Decryption failed: %v", err)
	}

	logrus.Printf("Decryption completed.")
	logrus.Printf("Writting to file...")

	/* Write decrypted data to the output file */
	_, err = f.Write(dec)
	if err != nil {
		logrus.Fatalf("Failed to write to file: %v", err)
	}

	/* Close the output file */
	err = f.Close()
	if err != nil {
		logrus.Fatalf("Failed to finalize file write: %v", err)
	}

	/* Done */
	logrus.Printf("Done.")

}
