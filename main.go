package main

import (
	"compare/util"
	"log"
	"os"
)

func main() {
	message := "berhasil..."
	encryption := util.Encryption{}
	encrypted, err := encryption.EncodeWithSecret(message)
	if err != nil {
		log.Panicln(err)
	}

	err = saveToFile("encrypted.txt", encrypted)
	if err != nil {
		log.Panicln(err)
	}

	encodedContent, err := readFromFile("encrypted.txt")
	if err != nil {
		log.Panicln(err)
	}

	decrypted, err := encryption.DecodeWithSecret(encodedContent)
	if err != nil {
		log.Panicln(err)
	}
	log.Println("go decrypted:", decrypted)

	log.Println("Hasil enkripsi telah disimpan di encrypted.txt")
}

func saveToFile(filename string, content string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	if err != nil {
		return err
	}

	return nil
}

func readFromFile(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return "", err
	}

	fileSize := stat.Size()
	fileContent := make([]byte, fileSize)
	_, err = file.Read(fileContent)
	if err != nil {
		return "", err
	}

	return string(fileContent), nil
}
