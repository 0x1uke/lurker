package cryptography

import (
	"crypto/rand"
	"math/big"

	"lurker/lurker/constants"
)

func RandomInt(min, max int64) int {
	nBig, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		panic(err)
	}
	n := nBig.Int64()
	return int(n)
}

func RandomAESKey() {
	constants.GlobalKey = make([]byte, 16)
	_, err := rand.Read(constants.GlobalKey[:])
	if err != nil {
		panic(err)
	}
}
