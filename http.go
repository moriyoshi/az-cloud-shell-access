package main

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

func readBody(resp *http.Response) ([]byte, error) {
	var b []byte
	var err error
	if resp.ContentLength != -1 {
		b = make([]byte, resp.ContentLength)
		_, err = io.ReadFull(resp.Body, b)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}
	} else {
		b, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}
	}
	return b, nil
}

func readResponse(resp *http.Response) ([]byte, bool, error) {
	var b []byte
	var err error
	if resp.Body != nil {
		defer resp.Body.Close()
		b, err = readBody(resp)
		if err != nil {
			return nil, false, err
		}
	}
	return b, resp.StatusCode >= 200 && resp.StatusCode < 300, err
}

type PollingHttpClient struct {
	Transport        http.RoundTripper
	MaxRedirectCount int
}

func (phc *PollingHttpClient) Do(req *http.Request) (*http.Response, error) {
	_req := req
	var i int
	if phc.MaxRedirectCount >= 0 {
		i = phc.MaxRedirectCount + 1
	} else {
		i = -1
	}
	for {
		i--
		if i == -1 {
			break
		}
		resp, err := phc.Transport.RoundTrip(_req)
		if err != nil {
			return nil, err
		}

		switch resp.StatusCode {
		default:
			return resp, err
		case 301, 302, 303:
			if _req == req {
				_req = _req.Clone(_req.Context())
				_req.Method = "GET"
			}
		case 307, 308:
		}
		it := 1
		if v := resp.Header.Get("retry-after"); v != "" {
			it, err = strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("failed to parse retry-after header: %w: %s", err, v)
			}
		}
		time.Sleep(time.Duration(it) * time.Second)
	}
	return &http.Response{StatusCode: http.StatusTooManyRequests}, fmt.Errorf("too many redirects (%d)", phc.MaxRedirectCount)
}
