package env

import (
	"os"
)

func GetSecretKey() string {
	value := os.Getenv("SECRET_KEY")
	if value == "" {
		value = "your_secret_key"
	}
	return value
}
