package seks

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/nacl/box"
	"strings"
)

func KeyGen() (string, string) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", ""
	}
	pubs := "public-key-" + hex.EncodeToString(pub[:])
	privs := "SECRET-KEY-" + strings.ToUpper(hex.EncodeToString(priv[:]))
	return pubs, privs
}

func ReadKey(s string) ([32]byte, error) {
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "public-key-")
	s = strings.TrimPrefix(s, "secret-key-")
	b, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, errors.New("invalid key")
	}
	return [32]byte(b[0:32]), nil
}

func ran() [24]byte {
	var b [24]byte
	_, err := rand.Reader.Read(b[:])
	if err != nil {
		panic(err)
	}
	return b
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

func unArmour(s string) ([]byte, error) {
	start := strings.Index(s, seksHeader) + len(seksHeader)
	end := strings.Index(s, seksFooter)
	s = s[start:end]
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, " ", "")
	return base64.StdEncoding.DecodeString(s)
}

func EncryptString(data string, toPubKey string, fromPrivKey string) (string, error) {
	b, err := EncryptBytes([]byte(data), toPubKey, fromPrivKey)
	if err != nil {
		return "", err
	}
	return armour(b), nil
}

func EncryptArmour(b []byte, toPubKey string, fromPrivKey string) ([]byte, error) {
	b, err := EncryptBytes(b, toPubKey, fromPrivKey)
	if err != nil {
		return nil, err
	}
	return []byte(armour(b)), nil
}

func EncryptBytes(data []byte, toPubKey string, fromPrivKey string) ([]byte, error) {
	var nonce = ran()
	pubKey, err := ReadKey(toPubKey)
	if err != nil {
		return nil, err
	}
	privKey, err := ReadKey(fromPrivKey)
	if err != nil {
		return nil, err
	}
	var out []byte = nonce[:]
	return box.Seal(out, data, &nonce, &pubKey, &privKey), nil
}

func DecryptString(data string, fromPubKey string, toPrivKey string) (string, error) {
	b, err := unArmour(data)
	if err != nil {
		return "", err
	}
	out, err := DecryptBytes(b, fromPubKey, toPrivKey)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func DecryptBytes(data []byte, fromPubKey string, toPrivKey string) ([]byte, error) {
	nonce := [24]byte(data[0:24])
	pubKey, err := ReadKey(fromPubKey)
	if err != nil {
		return nil, err
	}
	privKey, err := ReadKey(toPrivKey)
	if err != nil {
		return nil, err
	}
	out, ok := box.Open(nil, data[24:], &nonce, &pubKey, &privKey)
	if !ok {
		return nil, errors.New("decryption failed")
	}
	return out, nil
}

func DecryptArmour(data []byte, fromPubKey string, toPrivKey string) ([]byte, error) {
	b, err := unArmour(string(data))
	if err != nil {
		return nil, err
	}
	out, err := DecryptBytes(b, fromPubKey, toPrivKey)
	if err != nil {
		return nil, err
	}
	return out, nil
}
