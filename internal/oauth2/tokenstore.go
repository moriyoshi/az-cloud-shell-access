package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

type SimpleTokenStore struct {
	path      string
	authority string
	now       func() time.Time
}

type ErrTokenStoreContentBroken struct{}

func (*ErrTokenStoreContentBroken) Error() string {
	return "invalid token"
}

type ErrTokenExpired struct {
	t time.Time
}

func (e *ErrTokenExpired) Error() string {
	return fmt.Sprintf("token expired at %v", e.t.Format(time.RFC3339Nano))
}

type TokensSet []*Tokens

func (s *SimpleTokenStore) Store(ctx context.Context, t *Tokens) error {
	l := flock.New(s.path)
	err := l.Lock()
	if err != nil {
		return err
	}
	defer l.Unlock() //nolint:errcheck
	var f *os.File
	defer func() {
		if f != nil {
			f.Close()
		}
		if err == nil {
			err = os.Rename(f.Name(), s.path)
		}
		if err != nil {
			os.Remove(f.Name())
		}
	}()
	f, err = os.CreateTemp(filepath.Dir(s.path), filepath.Base(s.path)+".*")
	if err != nil {
		return err
	}
	ts, err := s.readAll(ctx)
	if err != nil {
		return err
	}
	var updated bool
	for i, _t := range ts {
		if _t.Authority == s.authority {
			ts[i] = t
			updated = true
		}
	}
	if !updated {
		t.Authority = s.authority
		ts = append(ts, t)
	}
	err = json.NewEncoder(f).Encode(ts)
	if err != nil {
		return err
	}
	return nil
}

func (s *SimpleTokenStore) readAll(ctx context.Context) (TokensSet, error) {
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	var ts TokensSet
	if len(b) != 0 {
		err = json.Unmarshal(b, &ts)
		if err != nil {
			return nil, err
		}
		for _, t := range ts {
			if !t.Valid() {
				return nil, new(ErrTokenStoreContentBroken)
			}
		}
	}
	return ts, nil
}

func (s *SimpleTokenStore) Fetch(ctx context.Context) (*Tokens, error) {
	l := flock.New(s.path)
	err := l.RLock()
	if err != nil {
		return nil, err
	}
	defer l.Unlock() //nolint:errcheck
	ts, err := s.readAll(ctx)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	for _, t := range ts {
		if t.Authority == s.authority {
			return t, nil
		}
	}
	return nil, nil
}

func NewSimpleTokenStore(path string, authority string, nowGetter func() time.Time) *SimpleTokenStore {
	return &SimpleTokenStore{
		path:      path,
		authority: authority,
		now:       nowGetter,
	}
}
