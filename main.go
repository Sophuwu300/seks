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

	encrypted, err := sopHex.UnMarshall(`-----BEGIN SEKS SECRET-----
A+=PEEM3<3PI<++1VE+=VS1O+L+H1AN3
=L3HI+MPM33OE+3NANN1NASNSII=MV+N
1+P3VSOA+SOVLSL3VE=+EHM++LSPEAIM
SLI3NPMPN3IMMP=V<VS1N31AHPHAI1=S
+3P=1ISMIHALS3VHL=V3O3=1V=<1SI1H
E1HH=H3=IVE+OE=H+E=SE<VL1V13SIH=
3AP<OA3O=HNELO3PNL3N+1LO<I3SMOP<
VSEH<HEOIVOHSMLV=HH=3MAO3HMSSSEV
==E3AOO<HPOMSN<PAE1HNVP<NP+AVO+O
3ISIHAP1PE=1VPS<O1S<+LN+H=E3MLV+
-----END SEKS SECRET-----
`)
	if err != nil {
		fmt.Println(err)
		return
	}
	salt := encrypted[0:32]
	//salt := ran()
	hash := sha256.New()
	hash.Write(passwd)
	hash.Write(salt)

	var key [32]byte
	copy(key[:], hash.Sum(nil))

	//var nonce = [24]byte(ran()[0:24])
	//salt = append(salt[:], nonce[:]...)
	//message := []byte("I like to eat apples and bananas. However, I do not like to eat oranges. Cars can drive!")
	//encrypted := secretbox.Seal(salt, message, &nonce, &key)

	//fmt.Println(sopHex.Marshall(encrypted))

	deNonce := [24]byte(encrypted[32 : 32+24])
	decrypted, boolEnlon := secretbox.Open(nil, encrypted[32+24:], &deNonce, &key)
	if boolEnlon != true {
		fmt.Println("OOPS")
		return
	}
	fmt.Println(string(decrypted))

}