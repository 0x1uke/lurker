# Lurker
Lurker is a cross-platform, companion implant to Cobalt Strike built with Go

Lurker is currently tested on:
* Windows
* Linux
* macOS

## Commands
Lurker supports the following commands:
* sleep - Adjust Lurker's check-in time
* shell - Run commands on the target
* upload - Upload files to a target machine
* download - Download files from a target machine
* exit - Terminate Lurker's process
* cd - Change directories
* ls - List current working directory contents
* pwd - Display the current working directory

More commands are under development

## Getting Started
1. Clone the Lurker repo
2. Run the `keyExtract.py` script in the same directory as the team server's `.cobaltstrike.beacon_keys` file
3. Copy the RSA public key into the `constants.go`'s `RsaPublicKey` variable
4. Edit the remaining `constants.go` variables with the desired configuration
5. Create a new GET/POST block in the Malleable C2 profile using the same format as `sample.profile`
6. Set the `GOOS` and `GOARCH` env variables to determine Lurker's target OS and architecture
7. In the root directory, `go build main.go`

## Disclaimer
Lurker is for authorized use and for research purposes only

## Acknowledgement
Lurker is refactored from and built on @darkr4y's Geacon project (https://github.com/darkr4y/geacon)
