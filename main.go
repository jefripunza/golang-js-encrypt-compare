package main

import (
	"compare/util"
	"fmt"
	"log"
)

func main() {
	message := "berhasil..."
	log.Println("GO Message:", message)

	// ============================================================
	// ============================================================

	encryption := util.Encryption{}
	encrypted, err := encryption.EncodeWithSecret(message)
	if err != nil {
		log.Panicln(err)
	}
	fmt.Println("GO Encode:", encrypted)

	err = util.SaveToFile("encrypted.txt", encrypted)
	if err != nil {
		log.Panicln(err)
	}

	encodedContent, err := util.ReadFromFile("encrypted.txt")
	if err != nil {
		log.Panicln(err)
	}

	decrypted, err := encryption.DecodeWithSecret(encodedContent)
	if err != nil {
		log.Panicln(err)
	}
	fmt.Println("GO Decode:", decrypted)

	log.Println("Hasil enkripsi telah disimpan di encrypted.txt")

	// ============================================================
	// ============================================================

	// ============================================================
	// ============================================================
}
