package constants

import (
	"time"
)

// Be wary of extra white space causing errors
var (
	RsaPublicKey = []byte(`-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----`)

	Url                         = "127.0.0.1:443"
	PlainHTTP                   = "http://"
	SslHTTP                     = "https://"
	GetUri                      = "/load"
	PostUri                     = "/submit.php?id="
	GetUrl                      = SslHTTP + Url + GetUri
	PostUrl                     = SslHTTP + Url + PostUri
	UserAgent                   = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; BOIE9;ENUS)"
	WaitTime                    = 10000 * time.Millisecond
	VerifySSLCert               = true
	TimeOut       time.Duration = 10 //seconds

	IV        = []byte("abcdefghijklmnop")
	GlobalKey []byte
	AesKey    []byte
	HmacKey   []byte
	Counter   = 0
)

const (
	DebugMode = true
)
