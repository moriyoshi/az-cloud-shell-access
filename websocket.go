package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type WSReadWriter struct {
	conn           *websocket.Conn
	packetOriented bool
	ci             uintptr
	cmu            sync.RWMutex
	ctx            context.Context
	rbc            chan []byte
	rb             []byte
	rtt            *time.Ticker
	rbl            sync.Mutex
	rd             time.Time
	rdmu           sync.RWMutex
	rerr           error
	cic            chan struct{}
	wbc            chan []byte
	wbcc           uintptr
	wtt            *time.Ticker
	wd             time.Time
	wdmu           sync.RWMutex
	werr           error
	wg             sync.WaitGroup
	wt             int
}

func (rw *WSReadWriter) reader() {
	defer rw.wg.Done()
	defer rw.rtt.Stop()
	defer close(rw.rbc)
outer:
	for {
		t, p, err := rw.conn.ReadMessage()
		if err != nil {
			rw.rerr = err
			break outer
		}
		if len(p) > 0 && (t == websocket.BinaryMessage || t == websocket.TextMessage) {
			select {
			case <-rw.ctx.Done():
				break outer
			case rw.rbc <- p:
			}
		}
	}
}

func (rw *WSReadWriter) writer() {
	defer rw.wg.Done()
	defer rw.wtt.Stop()
	defer rw.conn.Close()
outer:
	for {
		select {
		case <-rw.ctx.Done():
			break outer
		case <-rw.cic:
			rw.conn.WriteMessage(websocket.CloseMessage, []byte{}) //nolint: errcheck
		case b := <-rw.wbc:
			if b == nil {
				break outer
			}
			err := rw.conn.WriteMessage(rw.wt, b)
			if err != nil {
				rw.werr = err
				break outer
			}
		}
	}
}

func (rw *WSReadWriter) CloseAsync(graceful bool) bool {
	if !atomic.CompareAndSwapUintptr(&rw.ci, 0, 1) {
		return false
	}
	var d time.Duration
	if graceful {
		close(rw.cic)
		d = time.Duration(10) * time.Second
	} else {
		d = 0
	}
	t := time.NewTimer(d)
	rw.wg.Add(1)
	go func() {
		defer rw.wg.Done()
		select {
		case <-rw.ctx.Done():
			t.Stop()
		case <-t.C:
			if atomic.CompareAndSwapUintptr(&rw.wbcc, 0, 1) {
				rw.cmu.Lock()
				close(rw.wbc)
				rw.cmu.Unlock()
			}
		}
	}()
	return true
}

func (rw *WSReadWriter) Close() error {
	rw.CloseAsync(true)
	rw.wg.Wait()
	return nil
}

func (rw *WSReadWriter) Read(b []byte) (int, error) {
	if atomic.LoadUintptr(&rw.ci) != 0 {
		return 0, fmt.Errorf("connection is closing")
	}
	rw.rbl.Lock()
	defer rw.rbl.Unlock()
	now := time.Now()
	rw.rdmu.RLock()
	c := !rw.rd.IsZero() && !now.Before(rw.rd)
	rw.rdmu.RUnlock()
	if c {
		return 0, os.ErrDeadlineExceeded
	}

	eof := false
	var err error

	if rw.packetOriented {
		if len(rw.rb) == 0 {
		outer1:
			for {
				select {
				case bb := <-rw.rbc:
					if bb == nil {
						eof = true
					} else {
						rw.rb = append(rw.rb, bb...)
					}
					break outer1
				case <-rw.ctx.Done():
					err = fmt.Errorf("operation canceled")
					break outer1
				case t := <-rw.rtt.C:
					if t.IsZero() {
						err = fmt.Errorf("operation canceled")
						break outer1
					}
					rw.rdmu.RLock()
					c := !rw.rd.IsZero() && !t.Before(rw.rd)
					rw.rdmu.RUnlock()
					if c {
						err = os.ErrDeadlineExceeded
						break outer1
					}
				}
			}
		}
	} else {
	outer2:
		for len(rw.rb) < len(b) {
			select {
			case bb := <-rw.rbc:
				if bb == nil {
					eof = true
				} else {
					rw.rb = append(rw.rb, bb...)
				}
			case <-rw.ctx.Done():
				err = fmt.Errorf("operation canceled")
				break outer2
			case t := <-rw.rtt.C:
				if t.IsZero() {
					err = fmt.Errorf("operation canceled")
					break outer2
				}
				rw.rdmu.RLock()
				c := !rw.rd.IsZero() && !t.Before(rw.rd)
				rw.rdmu.RUnlock()
				if c {
					err = os.ErrDeadlineExceeded
					break outer2
				}
			}
		}
	}
	if err != nil {
		return 0, err
	}
	if rw.rb == nil && eof {
		return 0, io.EOF
	}
	if len(rw.rb) < len(b) {
		n := len(rw.rb)
		copy(b, rw.rb)
		rw.rb = nil
		return n, err
	} else {
		copy(b, rw.rb[:len(b)])
		rw.rb = rw.rb[len(b):]
		if len(rw.rb) == 0 {
			rw.rb = nil
		}
		return len(b), err
	}
}

func (rw *WSReadWriter) Write(b []byte) (int, error) {
	if atomic.LoadUintptr(&rw.ci) != 0 {
		return 0, fmt.Errorf("connection is closing")
	}
	rw.cmu.RLock()
	defer rw.cmu.RUnlock()
	now := time.Now()
	rw.wdmu.RLock()
	c := !rw.wd.IsZero() && !now.Before(rw.wd)
	rw.wdmu.RUnlock()
	if c {
		return 0, os.ErrDeadlineExceeded
	}
outer:
	for {
		select {
		case <-rw.ctx.Done():
			return 0, fmt.Errorf("operation canceled")
		case rw.wbc <- b:
			return len(b), nil
		case t := <-rw.wtt.C:
			if t.IsZero() {
				return 0, fmt.Errorf("operation canceled")
			}
			rw.wdmu.RLock()
			c := !rw.wd.IsZero() && !t.Before(rw.wd)
			rw.wdmu.RUnlock()
			if c {
				break outer
			}
		}
	}
	return 0, os.ErrDeadlineExceeded
}

func (rw *WSReadWriter) SetReadDeadline(t time.Time) error {
	rw.rdmu.Lock()
	defer rw.rdmu.Unlock()
	rw.rd = t
	return nil
}

func (rw *WSReadWriter) SetWriteDeadline(t time.Time) error {
	rw.wdmu.Lock()
	defer rw.wdmu.Unlock()
	rw.wd = t
	return nil
}

func (rw *WSReadWriter) SetDeadline(t time.Time) error {
	err := rw.SetReadDeadline(t)
	if err != nil {
		return err
	}
	return rw.SetWriteDeadline(t)
}

func NewWSReadWriter(ctx context.Context, conn *websocket.Conn, writerMessageType int, packetOriented bool) *WSReadWriter {
	rw := &WSReadWriter{
		conn:           conn,
		packetOriented: packetOriented,
		ctx:            ctx,
		rbc:            make(chan []byte, 32),
		rtt:            time.NewTicker(time.Second),
		cic:            make(chan struct{}, 1),
		wbc:            make(chan []byte, 32),
		wt:             writerMessageType,
		wtt:            time.NewTicker(time.Second),
	}
	conn.SetCloseHandler(func(code int, text string) error {
		atomic.StoreUintptr(&rw.ci, 1)
		if atomic.CompareAndSwapUintptr(&rw.wbcc, 0, 1) {
			rw.cmu.Lock()
			close(rw.wbc)
			rw.cmu.Unlock()
		}
		return nil
	})
	rw.wg.Add(1)
	go rw.reader()
	rw.wg.Add(1)
	go rw.writer()
	return rw
}
