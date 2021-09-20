//go:build aix || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos
// +build aix dragonfly freebsd linux netbsd openbsd solaris zos

package main

import (
	"golang.org/x/sys/unix"
)

const TCSBRKP = unix.TCSBRKP

func (rw *TerminalReadWriter) SendBreak(duration int) error {
	return unix.IoctlSetInt(int(rw.Fd()), TCSBRKP, duration)
}
