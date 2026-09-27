//go:build !linux

package capture

import (
	"context"
	"errors"
	"os"
	"time"
)

func Run(context.Context, string, int, func([]byte, int, string, time.Time), func(uint64)) error {
	return errors.New("live packet capture is Linux-only; use -replay for fixture verification")
}
func RSS() uint64              { return 0 }
func StopSignals() []os.Signal { return []os.Signal{os.Interrupt} }
