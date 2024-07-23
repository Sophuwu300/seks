package main

import (
	"fmt"
	"os"
	"sophuwu.site/seks"
)

func main() {
	if len(os.Args) < 4 {
		os.Exit(1)
	}
	b, e := os.ReadFile(os.Args[3])
	if e != nil {
		fmt.Println(e)
		os.Exit(1)
	}
	if os.Args[1] == "e" {
		fmt.Println(seks.Encrypt(string(b), os.Args[2]))
	}
	if os.Args[1] == "d" {
		s, err := seks.Decrypt(string(b), os.Args[2])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(s)
	}
}
