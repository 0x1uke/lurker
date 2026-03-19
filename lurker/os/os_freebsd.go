package os

import (
	"encoding/binary"
	"os"
	"os/user"
	"runtime"
)

func GetOSVersion() string {
	return "0.0"
}

func IsHighPriv() bool {
	return os.Geteuid() == 0
}

func IsOSX64() bool {
	return runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"
}

func IsProcessX64() bool {
	return runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"
}

func GetCodePageANSI() []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, 1252)
	return b
}

func GetCodePageOEM() []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, 437)
	return b
}

func GetUsername() string {
	user, err := user.Current()
	if err != nil {
		return "?"
	}
	return user.Username
}
