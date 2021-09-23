//go:build aix || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos
// +build aix dragonfly freebsd linux netbsd openbsd solaris zos

package main

import (
	"golang.org/x/sys/unix"

	"time"
)

func (rw *TerminalReadWriter) SetVMinVTime(vmin int, vtime time.Duration) error {
	tos, err := unix.IoctlGetTermios(int(rw.Fd()), unix.TCGETS)
	if err != nil {
		return err
	}
	tos.Cc[unix.VMIN] = byte(vmin)
	tos.Cc[unix.VTIME] = byte(time.Duration(vtime) / (time.Second / 10))
	return unix.IoctlSetTermios(int(rw.Fd()), unix.TCSETS, tos)
}
