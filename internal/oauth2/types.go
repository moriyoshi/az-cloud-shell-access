package oauth2

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

type DurationInSeconds time.Duration

func (i *DurationInSeconds) UnmarshalJSON(b []byte) error {
	var s interface{}
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	switch s := s.(type) {
	case string:
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse a string as a duration: %w", err)
		}
		*i = DurationInSeconds(v) * DurationInSeconds(time.Second)
	case int64:
		*i = DurationInSeconds(s) * DurationInSeconds(time.Second)
	default:
		return fmt.Errorf("unexpected value: %#v", s)
	}
	return nil
}
