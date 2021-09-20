//go:build windows
// +build windows

package main

func (rw *TerminalReadWriter) SendBreak(duration int) error {
	return nil
}
