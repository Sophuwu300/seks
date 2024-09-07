package main

import "sophuwu.site/seks"

func main() {
       	pub, priv := seks.KeyGen()
	println(pub)
	println(priv)
}