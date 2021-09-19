package oauth2

import (
	"fmt"
	"io"
	"net/http"
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
