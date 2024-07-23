package main

import (
	"fmt"
	"os"
	"sophuwu.site/seks"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "gen" {
		pub, priv := seks.KeyGen()
		fmt.Println(pub)
		fmt.Println(priv)
		return
	}
	if len(os.Args) != 5 {
		return
	}
	keys := make(map[byte]string)
	keys[os.Args[2][0]] = os.Args[2]
	keys[os.Args[3][0]] = os.Args[3]
	b, err := os.ReadFile(os.Args[4])
	if err != nil {
		fmt.Println(err)
		return
	}
	if os.Args[1] == "e" {
		b, err = seks.EncryptArmour(b, keys['p'], keys['S'])
	} else if os.Args[1] == "d" {
		b, err = seks.DecryptArmour(b, keys['p'], keys['S'])
	}
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(b))
}
