/*
 * SEKS: Secrets Encrypted Kept Safe
 */
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/term"
	"os"
	"seks/sopHex"
	"syscall"
)

func ran() []byte {
	var b [32]byte
	_, err := rand.Reader.Read(b[:])
	if err != nil {
		panic(err)
	}
	return b[:]
}

func decrypt(encrypted []byte, key [32]byte) string {
	deNonce := [24]byte(encrypted[32 : 32+24])
	decrypted, boolEnlon := secretbox.Open(nil, encrypted[32+24:], &deNonce, &key)
	if boolEnlon != true {
		return "Error decrypting"
	}
	return string(decrypted)
}

func hashPasswd(salt []byte, passwd []byte) [32]byte {
	hash := sha256.New()
	hash.Write(passwd)
	hash.Write(salt)
	var key [32]byte
	copy(key[:], hash.Sum(nil))
	return key
}

func main() {
	// NaCl crypto_box symmetric encryption
	// Make a bbolt database
	// Add buckets for categories of secrets
	// User makes a password for each bucket

	if len(os.Args) < 2 {
		fmt.Println("Usage: seks -e|-d")
		return
	}
	e := false
	if os.Args[1] == "-e" {
		e = true
		fmt.Println("Encrypting. ")
	} else if os.Args[1] == "-d" {
		fmt.Println("Decrypting. ")
	} else {
		fmt.Println("Usage: seks -e|-d")
		return
	}
	fmt.Print("Enter password Your Password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println(err)
		return
	}
	var buff bytes.Buffer
	fmt.Printf("\nEnter input data ending with EOF (Ctrl-D):\n")
	_, err = buff.ReadFrom(os.Stdin)
	if err != nil {
		fmt.Println(err)
		return
	}
	var result string
	if e {
		salt := ran()
		key := hashPasswd(salt, password)
		var nonce = [24]byte(ran()[0:24])
		salt = append(salt[:], nonce[:]...)
		result = sopHex.Marshall(secretbox.Seal(salt, buff.Bytes(), &nonce, &key))
	} else {
		var crypt []byte
		crypt, err = sopHex.UnMarshall(buff.String())
		if err != nil {
			fmt.Println(err)
			return
		}
		result = decrypt(crypt, hashPasswd(crypt[0:32], password))
	}
	fmt.Printf("-----Result-----\n")
	fmt.Println(result)

}