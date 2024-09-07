package main

import (
	"sophuwu.site/seks"
)

const pk = "public-key-158d1a9fe9c919964e516fdbd55a27961ee56c91598d3691ab380e3f49d49f75"
const sk = "SECRET-KEY-0D24C35A60E967F965D483C4D330975A2BABD0087B2938B9F2F07393F6CB8E53"

func main() {
	println(pk + "\n" + sk)
	b := []byte("uwu")
	println("message:\n" + string(b))
	b, _ = seks.EncryptArmour(b, pk, sk)
	println("encryption:\n" + string(b))
	b, _ = seks.DecryptArmour(b, pk, sk)
	println("decrypted message:\n" + string(b))
}
