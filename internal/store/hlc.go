package store

import (
	"sync"
	"time"
)

// HLC is a hybrid logical clock timestamp: the high 48 bits are wall-clock
// milliseconds since the Unix epoch, the low 16 bits a logical counter.
// Comparing two HLCs as integers orders them causally within a region and
// "close enough to real time" across regions, even when a laptop's clock
// jumps backwards after sleep.
type HLC uint64

const hlcCounterBits = 16

// MakeHLC builds a timestamp from its parts.
func MakeHLC(wallMs int64, counter uint16) HLC {
	return HLC(uint64(wallMs)<<hlcCounterBits | uint64(counter))
}

// WallMs returns the physical part in Unix milliseconds.
func (h HLC) WallMs() int64 { return int64(uint64(h) >> hlcCounterBits) }

// Counter returns the logical part.
func (h HLC) Counter() uint16 { return uint16(h) }

// Time returns the physical part as a time.Time.
func (h HLC) Time() time.Time { return time.UnixMilli(h.WallMs()) }

// Clock issues monotonically increasing HLC timestamps.
type Clock struct {
	mu   sync.Mutex
	last HLC
	now  func() time.Time
}

// NewClock returns a clock reading the given wall clock (time.Now when nil).
func NewClock(now func() time.Time) *Clock {
	if now == nil {
		now = time.Now
	}
	return &Clock{now: now}
}

// Now returns a timestamp strictly greater than every one issued or observed
// before. If the wall clock went backwards, the physical part stays put and
// the counter advances.
func (c *Clock) Now() HLC {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = c.next(c.last)
	return c.last
}

// Observe folds in a timestamp seen from another region, so that anything
// issued afterwards orders after it.
func (c *Clock) Observe(remote HLC) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if remote > c.last {
		c.last = remote
	}
}

func (c *Clock) next(last HLC) HLC {
	wall := c.now().UnixMilli()
	if wall > last.WallMs() {
		return MakeHLC(wall, 0)
	}
	if last.Counter() == 1<<hlcCounterBits-1 {
		// Counter exhausted within one millisecond: borrow the next millisecond.
		return MakeHLC(last.WallMs()+1, 0)
	}
	return last + 1
}
