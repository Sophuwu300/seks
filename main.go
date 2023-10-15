/*
 * SEKS: Secrets Encrypted Kept Safe
 */
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
	_ "time"
)

const hexKey string = "SOPHIE+MAL1VN=<3"

type hexEncoder []byte

func hexString(b []byte) string {
	var s string
	for i := 0; i < len(b); i++ {
		s += string(hexKey[(b[i]>>4)&15])
		s += string(hexKey[b[i]&15])
	}
	return s
}

func ran() []byte {
	var b [32]byte
	_, err := rand.Reader.Read(b[:])
	if err != nil {
		panic(err)
	}
	return b[:]
}

func main() {
	// NaCl crypto_box symmetric encryption
	// Make a bbolt database
	// Add buckets for categories of secrets
	// User makes a password for each bucket

	passwd := []byte("TestPassword")

	salt := ran()
	hash := sha256.New()
	hash.Write(passwd)
	hash.Write(salt)

	var key [32]byte
	copy(key[:], hash.Sum(nil))

	var nonce = [24]byte(ran()[0:24])

	message := []byte("I like to eat apples and bananas. However, I do not like to eat oranges. Cars can drive!")
	encrypted := secretbox.Seal(nonce[:], message, &nonce, &key)

	fmt.Println(hexString(encrypted))

}