package encoding

import (
	"fmt"
	"strings"
)

// var SEKSSet string = `SOPHIE+MAL1VN=<3` // short for test purposes
var SEKSSet string = `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789$£`

const seksHeader string = "-----BEGIN SOME ENCRYPTION KEY STUFF-----"
const seksFooter string = "-----END SOME ENCRYPTION KEY STUFF-----"

func Armour(b []byte) string {
	var s string
	for i := 0; i < len(b); i++ {
		if i%69 == 0 {
			s += "\n"
		}
		s += string(SEKSSet[(b[i]>>4)&15]) + string(SEKSSet[b[i]&15])
	}
	return seksHeader + s + "\n" + seksFooter + "\n"
}

func UnArmour(s string) ([]byte, error) {
	begin := strings.Index(s, seksHeader)
	end := strings.Index(s, seksFooter)
	if begin < 0 || end < 0 {
		return nil, fmt.Errorf("sopHex UnMarshall: invalid seks secret")
	}
	s = s[begin+len(seksHeader) : end]
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.TrimPrefix(s, seksHeader)
	s = strings.TrimSuffix(s, seksFooter)
	s = strings.ReplaceAll(s, " ", "")
	var b []byte
	var n int
	for i, v := range s {
		n = index(v)
		if n == -1 {
			return nil, fmt.Errorf("sopHex UnMarshall: invalid character %q at index %d", v, i)
		}
		if i%2 == 0 {
			b = append(b, byte(n<<4))
		} else {
			b[len(b)-1] |= byte(n)
		}
	}
	return b, nil
}

func index(c rune) (j int) {
	for j, v := range SEKSSet {
		if v == c {
			return j
		}
	}
	return -1
}