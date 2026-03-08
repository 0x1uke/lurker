package os

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
)

func GetOSVersion() string {
	cmd := exec.Command("sw_vers", "-productVersion")
	out, _ := cmd.CombinedOutput()
	return strings.TrimSpace(string(out))
}

func IsHighPriv() bool {
	fd, err := os.Open("/root")
	if err != nil {
		return false
	}
	fd.Close()
	return true
}

func IsOSX64() bool {
	cmd := exec.Command("sysctl", "hw.cpu64bit_capable")
	out, _ := cmd.CombinedOutput()
	out = bytes.ReplaceAll(out, []byte("hw.cpu64bit_capable: "), []byte(""))
	if strings.TrimSpace(string(out)) == "1" {
		return true
	}
	return false
}

func IsProcessX64() bool {
	if runtime.GOARCH == "amd64" {
		return true
	}
	return false
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
