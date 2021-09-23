package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/alessio/shellescape"
	"github.com/juju/utils/v3"
)

type ReadWriterWithDeadline interface {
	io.ReadWriter

	SetReadDeadline(time.Time) error
}

func expectAnyStringBy(rw ReadWriterWithDeadline, d time.Time) ([]byte, error) {
	rw.SetReadDeadline(d)                 //nolint:errcheck
	defer rw.SetReadDeadline(time.Time{}) //nolint:errcheck
	var b []byte
	rb := make([]byte, 1024)
outer:
	for {
		n, err := rw.Read(rb)
		b = append(b, rb[:n]...)
		if err != nil {
			if !os.IsTimeout(err) {
				return b, err
			}
			break outer
		}
	}
	return b, nil
}

func sendEmptyLine(rw ReadWriterWithDeadline) error {
	b := [2]byte{'\n', 0}
	n, err := rw.Write(b[:1])
	if err != nil || n == 0 {
		return fmt.Errorf("failed to write 1 bytes: %w", err)
	}
	n, err = io.ReadFull(rw, b[:])
	if err != nil {
		return fmt.Errorf("failed to read 2 bytes: %w", err)
	}
	if n != 2 || b[0] != 13 && b[1] != 10 {
		return fmt.Errorf("failed to read 2 bytes")
	}
	return nil
}

func injectEnvironmentVariablesBash(vars map[string]string, rw ReadWriterWithDeadline, nowGetter func() time.Time) error {
	prompt, err := expectAnyStringBy(rw, nowGetter().Add(time.Duration(5)*time.Second))
	if err != nil {
		return err
	}
	for k, v := range vars {
		b := []byte(fmt.Sprintf("export %s=%s\n", k, shellescape.Quote(v)))
		n, err := rw.Write(b)
		if err != nil {
			return fmt.Errorf("failed to write %d bytes: %w", len(b), err)
		}
		if n != len(b) {
			return fmt.Errorf("failed to write %d bytes", len(b))
		}
		eb := bytes.ReplaceAll(b, []byte{'\n'}, []byte{'\r', '\n'})
		rb := make([]byte, len(eb)+len(prompt))
		_, err = io.ReadFull(rw, rb)
		if err != nil {
			return fmt.Errorf("failed to read %d bytes: %w", len(rb), err)
		}
		if !bytes.Equal(eb, rb[:len(eb)]) || !bytes.Equal(prompt, rb[len(eb):]) {
			return fmt.Errorf("the counterpart returned unexpected string: %#v", rb)
		}
	}
	return sendEmptyLine(rw)
}

func injectEnvironmentVariablesPwsh(vars map[string]string, rw ReadWriterWithDeadline, nowGetter func() time.Time) error {
	prompt, err := expectAnyStringBy(rw, nowGetter().Add(time.Duration(5)*time.Second))
	if err != nil {
		return err
	}
	for k, v := range vars {
		b := []byte(fmt.Sprintf("$Env:%s=%s\n", k, utils.WinPSQuote(v)))
		n, err := rw.Write(b)
		if err != nil {
			return fmt.Errorf("failed to write %d bytes: %w", len(b), err)
		}
		if n != len(b) {
			return fmt.Errorf("failed to write %d bytes", len(b))
		}
		eb := bytes.ReplaceAll(b, []byte{'\n'}, []byte{'\r', '\n'})
		rb := make([]byte, len(eb)+len(prompt))
		_, err = io.ReadFull(rw, rb)
		if err != nil {
			return fmt.Errorf("failed to read %d bytes: %w", len(rb), err)
		}
		if !bytes.Equal(eb, rb[:len(eb)]) || !bytes.Equal(prompt, rb[len(eb):]) {
			return fmt.Errorf("the counterpart returned unexpected string: %#v", rb)
		}
	}
	return sendEmptyLine(rw)
}
