package main

import "sophuwu.site/seks/keyring"

func main() {
	pub, priv := keyring.KeyGen()
	println(pub)
	println(priv)
}
