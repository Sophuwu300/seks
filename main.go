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

func hexString(b []byte) string {
	var s string
	for i := 0; i < len(b); i++ {
		s += string(hexKey[(b[i]>>4)&15])
		s += string(hexKey[b[i]&15])
	}
	return s
}

func hexUnString(s string) []byte {
	var b []byte
	for i := 0; i < len(s); i += 2 {
		b = append(b, byte(hexKey[s[i]]<<4)|byte(hexKey[s[i+1]]))
	}
	return b
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

	//salt := ran()
	salt := hexUnString("3MN+1SML3OV<IVO1OMNENNL<MIOSMPP1ONOSL+=+NMPPVEOA++A<LPH1S3L+IIHA")
	hash := sha256.New()
	hash.Write(passwd)
	hash.Write(salt)

	var key [32]byte
	copy(key[:], hash.Sum(nil))

	//var nonce = [24]byte(ran()[0:24])

	//message := []byte("I like to eat apples and bananas. However, I do not like to eat oranges. Cars can drive!")
	//encrypted := secretbox.Seal(nonce[:], message, &nonce, &key)

	//fmt.Println(hexString(encrypted))
	//fmt.Println(hexString(salt))

	encrypted := hexUnString("AHNS=+H+IMNH+OHOAHI+A==3SVVLMVII<O+NH3MSE3=SO+<SNMI1EP1+LONHHE3==N1OESVPSMNHN1=1PNHHSVAPHE+HV31O+OVE3N3IM+OAAA+1=LSO<N+<+IA<S1P+HLM<+=S<EEA<31=O1OSOM1IN3HEV<AILHAS<+S+ONVVLM3=V=+OPLLNSLH<S+=LPSVMM<SPIMNE<EV<MIPOOH+NHO<3A3=IS+ESS3E+SMPEL313MOVL1<N1INSAAE1HS")
	var deNonce [24]byte = [24]byte(encrypted[0:24])
	decrypted, boolEnlon := secretbox.Open(nil, encrypted[24:], &deNonce, &key)
	if boolEnlon != true {
		fmt.Println("OOPS")
		return
	}
	fmt.Println(string(decrypted))
}