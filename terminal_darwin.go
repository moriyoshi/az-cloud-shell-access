//go:build darwin
// +build darwin

package main

import (
	"golang.org/x/sys/unix"
)

const TCSBRKP = 0x5425

func (rw *TerminalReadWriter) SendBreak(duration int) error {
	return unix.IoctlSetInt(int(rw.Fd()), TCSBRKP, duration)
}
