package cryptography

import (
	"math/rand"
	"time"

	"lurker/lurker/constants"
)

func RandomInt(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	return min + rand.Intn(max-min)
}

func RandomAESKey() {
	constants.GlobalKey = make([]byte, 16)
	_, err := rand.Read(constants.GlobalKey[:])
	if err != nil {
		panic(err)
	}
}
