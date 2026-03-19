package os

import (
	"encoding/binary"
	// "fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
	"syscall"
)

func arrayToString(x [65]int8) string {
	var buf [65]byte
	for i, b := range x {
		buf[i] = byte(b)
	}
	str := string(buf[:])
	if i := strings.Index(str, "\x00"); i != -1 {
		str = str[:i]
	}
	return str
}

func getUname() syscall.Utsname {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		// fmt.Printf("Uname: %v", err)
		return syscall.Utsname{} //nil
	}
	return uname
}

func GetOSVersion() string {
	uname := getUname()

	if len(uname.Release) > 0 {
		return arrayToString(uname.Release)
	}
	return "0.0"
}

func IsHighPriv() bool {
	return os.Geteuid() == 0
}

func IsOSX64() bool {
	uname := getUname()
	machine := arrayToString(uname.Machine)
	return machine == "x86_64" || machine == "aarch64"
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
