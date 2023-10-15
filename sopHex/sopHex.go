package sopHex

import "fmt"

const sopHexSet string = "SOPHIE+MAL1VN=<3"

const seksHeader string = `-----BEGIN SEKS SECRET-----
`
const seksFooter string = `
-----END SEKS SECRET-----
`

func Marshall(b []byte) string {
	var s string
	for i := 0; i < len(b); i++ {
		if i%16 == 0 {
			s += "\n"
		}
		s += string(sopHexSet[(b[i]>>4)&15]) + string(sopHexSet[b[i]&15])
	}
	return seksHeader + s + seksFooter
}

func UnMarshall(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("sopHex UnMarshall: invalid length %d", len(s))
	}
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
	for j, v := range sopHexSet {
		if v == c {
			return j
		}
	}
	return -1
}