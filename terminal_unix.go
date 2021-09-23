//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos
// +build aix darwin dragonfly freebsd linux netbsd openbsd solaris zos

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
