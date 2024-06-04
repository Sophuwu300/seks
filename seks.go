package seks

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
	"strings"
)

func ran() []byte {
	var b [32]byte
	_, err := rand.Reader.Read(b[:])
	if err != nil {
		panic(err)
	}
	return b[:]
}
func hashPasswd(salt []byte, passwd []byte) [32]byte {
	hash := sha256.New()
	hash.Write(passwd)
	hash.Write(salt)
	var key [32]byte
	copy(key[:], hash.Sum(nil))
	return key
}

const seksArmour = `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_`
const seksHeader = `-----BEGIN SOME ENCRYPTION KEY STUFF-----`
const seksFooter = `------END SOME ENCRYPTION KEY STUFF------`

func armour(b []byte) string {
	var s string
	var n uint = 0
	var m uint = 0
	for i := 0; i < 3-len(b)%3; i++ {
		b = append(b, 0)
	}
	for _, c := range b {
		n |= uint(c) << uint(m*8)
		m++
		if m == 3 {
			for j := 0; j < 4; j++ {
				s += string(seksArmour[n&63])
				n >>= 6
			}
			m = 0
			n = 0
		}
	}
	// add newlines
	for i := 0; i < len(s); i += len(seksHeader) {
		s = s[:i] + "\n" + s[i:]
	}
	return seksHeader + s + "\n" + seksFooter + "\n"
}

func Encrypt(data string, password string) string {
	return armour(encryptBytes([]byte(data), password))
}
func encryptBytes(data []byte, password string) []byte {
	salt := ran()
	key := hashPasswd(salt, []byte(password))
	var nonce = [24]byte(ran()[0:24])
	salt = append(salt[:], nonce[:]...)
	return secretbox.Seal(salt, data, &nonce, &key)
}

func Decrypt(data string, password string) (string, error) {
	b, err := unArmour(data)
	if err != nil {
		return "", err
	}
	return string(decryptBytes(b, password)), nil
}

func decryptBytes(encrypted []byte, pass string) []byte {
	salt := encrypted[:32]
	nonce := [24]byte(encrypted[32 : 32+24])
	key := hashPasswd(salt[:], []byte(pass))
	decrypted := make([]byte, len(encrypted)-32-24)
	decrypted, boolEnlon := secretbox.Open(nil, encrypted[32+24:], &nonce, &key)
	if boolEnlon != true {
		return nil
	}
	return decrypted
}

func unArmour(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.TrimPrefix(s, seksHeader)
	s = strings.TrimSuffix(s, seksFooter)
	s = strings.ReplaceAll(s, " ", "")
	var b []byte
	var n uint = 0
	var m uint = 0
	for _, c := range s {
		i := index(c)
		if i < 0 {
			return nil, fmt.Errorf("SEKS UnMarshall: invalid character")
		}
		n |= uint(i) << uint(m*6)
		m++
		if m == 4 {
			for j := 0; j < 3; j++ {
				b = append(b, byte(n&255))
				n >>= 8
			}
			m = 0
			n = 0
		}
	}
	if len(b) > 0 { // remove padding
		for i := 0; i < 3; i++ {
			if b[len(b)-1] == 0 {
				b = b[:len(b)-1]
			}
		}
	}
	return b, nil
}

func index(c rune) (j int) {
	for j, v := range seksArmour {
		if v == c {
			return j
		}
	}
	return -1
}
