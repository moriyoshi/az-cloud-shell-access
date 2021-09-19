package main

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

type TerminalReadWriter struct {
	*os.File
}

func (rw *TerminalReadWriter) ScreenSize() (int, int, error) {
	return term.GetSize(int(rw.Fd()))
}

func (rw *TerminalReadWriter) MakeRaw() (interface{}, error) {
	s, err := term.MakeRaw(int(rw.Fd()))
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (rw *TerminalReadWriter) Restore(state interface{}) error {
	if state, ok := state.(*term.State); !ok {
		return fmt.Errorf("unexpected state: %T", state)
	} else {
		return term.Restore(int(rw.Fd()), state)
	}
}
