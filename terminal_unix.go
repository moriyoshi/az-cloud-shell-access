//go:build aix || darwin || dragonfly || freebsd || netbsd || openbsd || solaris
// +build aix darwin dragonfly freebsd netbsd openbsd solaris

package main

import (
	"golang.org/x/sys/unix"

	"time"
)

func (rw *TerminalReadWriter) SendBreak(duration time.Duration) error {
	if err := unix.IoctlSetInt(int(rw.Fd()), unix.TIOCSBRK, 0); err != nil {
		return err
	}
	time.Sleep(duration)
	return unix.IoctlSetInt(int(rw.Fd()), unix.TIOCCBRK, 0)
}

func (rw *TerminalReadWriter) SetVMinVTime(vmin int, vtime time.Duration) error {
	tos, err := unix.IoctlGetTermios(int(rw.Fd()), unix.TIOCGETA)
	if err != nil {
		return err
	}
	tos.Cc[unix.VMIN] = byte(vmin)
	tos.Cc[unix.VTIME] = byte(time.Duration(vtime) / (time.Second / 10))
	return unix.IoctlSetTermios(int(rw.Fd()), unix.TIOCSETA, tos)
}
