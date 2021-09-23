//go:build windows
// +build windows

package main

func (rw *TerminalReadWriter) SendBreak(duration int) error {
	return nil
}

func (rw *TerminalReadWriter) SetVMinVTime(vmin int, vtime time.Duration) error {
	return nil
}
