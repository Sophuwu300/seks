package seks

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

const seksHeader = "-----BEGIN SOME ENCRYPTION KEY STUFF-----\n\n"
const seksFooter = "\n------END SOME ENCRYPTION KEY STUFF------"

func armour(b []byte) string {
	var s string
	s = base64.StdEncoding.EncodeToString(b)
	for i := 64; i < len(s); i += 64 {
		s = s[:i] + "\n" + s[i:]
	}
	return seksHeader + s + seksFooter
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
	start := strings.Index(s, seksHeader) + len(seksHeader)
	end := strings.Index(s, seksFooter)
	s = s[start:end]
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, " ", "")
	return base64.StdEncoding.DecodeString(s)
}
