package main

import (
	"io"
	"sync/atomic"
)

type meterFilter struct {
	r     io.Reader
	meter *int64
}

func NewMeter(i io.Reader, meter *int64) io.Reader {
	return &meterFilter{i, meter}
}

func (m *meterFilter) Read(b []byte) (int, error) {
	n, err := m.r.Read(b)
	atomic.AddInt64(m.meter, int64(n))
	return n, err
}
