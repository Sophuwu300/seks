package keyring

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/asdine/storm/v3"
	"golang.org/x/crypto/nacl/box"
	"strings"
)

const KEYHEADER = "----BEGIN SEKS PUBLIC KEY BLOCK-----"
const KEYFOOTER = "-----END SEKS PUBLIC KEY BLOCK-----"
const PRIVHEAD = "----BEGIN SEKS PRIVATE KEY BLOCK-----"
const PRIVFOOT = "-----END SEKS PRIVATE KEY BLOCK-----"

const KeyVersion = "SEKS1.0"

type PubKey struct {
	Name    string            `storm:"index"`
	Email   string            `storm:"index"`
	PubKey  [32]byte          `storm:"unique"`
	KeyID   string            `storm:"id"`
	Tags    map[string]string `storm:"index"`
	Version string            `storm:"index"`
}

func (p *PubKey) Export() (string, error) {
	s := KEYHEADER + "\n"
	s += "Version: " + p.Version + "\n"
	s += "Name: " + p.Name
	if p.Email != "" {
		s += " <" + p.Email + ">"
	}
	s += "\n"
	jsn, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return s + "\n" + hex.EncodeToString(p.PubKey[:]) + "\n" + string(jsn) + "\n" + KEYFOOTER, nil
}

type PrivKey struct {
	PubID     string `storm:"index"`
	Encrypted string `storm:"index"`
}

func KeyGen() (string, string) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", ""
	}

	pubs := "public-key-" + hex.EncodeToString(pub[:])
	privs := "SECRET-KEY-" + strings.ToUpper(hex.EncodeToString(priv[:]))
	return pubs, privs
}

var DB *storm.DB
