package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/keybase/go-triplesec"
)

func main() {

	/* Output tool start log */
	slog.Info("starting the eldim decryption tool")

	/* Command line flags with all needed data */
	inputFile := flag.String("in", "input.dat", "The encrypted file to decrypt.")
	outputFile := flag.String("out", "output.dat", "The file to save the decrypted data.")
	encryptionKey := flag.String("key", "Insecure", "The encryption password to decrypt the data.")

	flag.Parse()

	/* Print input and output file to log for documentation purposes */
	slog.Info("started", "input_file", *inputFile, "output_file", *outputFile)

	/* Delete any file that exists in the outputFile */
	os.Remove(*outputFile)

	/* Read the encrypted file to RAM */
	slog.Info("reading encrypted file to memory")
	encData, err := os.ReadFile(*inputFile)
	if err != nil {
		slog.Error("failed to read input file", "error", err)
		os.Exit(1)
	}
	slog.Info("file in memory", "size_bytes", len(encData))

	/* Create an output file */
	f, err := os.Create(*outputFile)
	if err != nil {
		slog.Error("failed to create output file", "error", err)
		os.Exit(1)
	}

	slog.Info("decrypting data")

	/*
	   Create a new TripleSec cipher

	   The number 4 being passed is the Cipher version, which is
	   currently the latest version supported by TripleSec.
	*/
	cipher, err := triplesec.NewCipher([]byte(*encryptionKey), nil, 4)
	if err != nil {
		slog.Error("failed to initialize the cryptographic engine", "error", err)
		os.Exit(1)
	}

	/* Decrypt the data in memory */
	dec, err := cipher.Decrypt(encData)
	if err != nil {
		slog.Error("decryption failed", "error", err)
		os.Exit(1)
	}

	slog.Info("decryption completed")
	slog.Info("writing to file")

	/* Write decrypted data to the output file */
	_, err = f.Write(dec)
	if err != nil {
		slog.Error("failed to write to file", "error", err)
		os.Exit(1)
	}

	/* Close the output file */
	err = f.Close()
	if err != nil {
		slog.Error("failed to finalize file write", "error", err)
		os.Exit(1)
	}

	/* Done */
	slog.Info("done")

}
