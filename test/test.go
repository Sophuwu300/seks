package main

import (
	"fmt"
	"git.sophuwu.site/seks"
	"os"
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
		s, _ := seks.Decrypt(string(b), os.Args[2])
		fmt.Println(s)
	}
}
