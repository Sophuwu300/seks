/*
 * SEKS: Secrets Encrypted Kept Safe
 */
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
	"seks/sopHex"
)

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
	salt = append(salt[:], nonce[:]...)
	message := []byte("I like to eat apples and bananas. However, I do not like to eat oranges. Cars can drive!")
	encrypted := secretbox.Seal(nil, message, &nonce, &key)

	fmt.Println(sopHex.Marshall(encrypted))
	/*
		deNonce := [24]byte(encrypted[0:24])
		decrypted, boolEnlon := secretbox.Open(nil, encrypted[24:], &deNonce, &key)
		if boolEnlon != true {
			fmt.Println("OOPS")
			return
		}
		fmt.Println(string(decrypted))

	*/
}