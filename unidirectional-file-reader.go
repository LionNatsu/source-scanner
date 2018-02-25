package main

import (
	"errors"
	"io"
)

const FileReaderBlockSize = 1024 * 4

var (
	ErrLookBack   = errors.New("UDFR: seeking back to offset not read is not allowed")
	ErrSeekEnd    = errors.New("UDFR: io.SeekEnd is not supported")
	ErrSeekWhence = errors.New("UDFR: invalid argument")
)

type UDFR struct {
	i      io.Reader
	buffer map[int64][]byte
	cur    int64
	edge   int64
	eof    bool
}

func NewUDFR(input io.Reader) *UDFR {
	return &UDFR{i: input, buffer: make(map[int64][]byte), edge: 0}
}

func (r *UDFR) Read(b []byte) (int, error) {
	if r.cur == r.edge && r.eof {
		return 0, io.EOF
	}
	var i int
	for i = 0; i != len(b); i++ {
		c, err := r.readByte(true)
		if err == io.EOF {
			return i, nil
		}
		if err != nil {
			return i, err
		}
		b[i] = c
	}
	return i, nil
}

func (r *UDFR) readByte(buffer bool) (byte, error) {
	if r.cur == r.edge && r.eof {
		return 0, io.EOF
	}
	frameIndex := r.cur / FileReaderBlockSize
	frameOffset := r.cur % FileReaderBlockSize
	frame, framePresent := r.buffer[frameIndex]

	var data byte
	var err error
	if r.cur == r.edge {
		// Reading on the edge
		if !framePresent {
			frame = make([]byte, FileReaderBlockSize)
			r.buffer[frameIndex] = frame
		}
		var preRead int
		preRead, err = r.i.Read(frame[frameOffset:])
		if err == io.EOF {
			r.eof = true
			return 0, io.EOF
		}
		if err == nil {
			r.cur++
			r.edge += int64(preRead)
			data = frame[frameOffset]
		}
	} else {
		// Reading in buffer
		if !framePresent {
			return 0, ErrLookBack
		}
		data = frame[frameOffset]
		r.cur++
	}
	return data, err
}

func (r *UDFR) Seek(offset int64, whence int, buffer bool) (int64, error) {
	switch whence {
	case io.SeekStart:
		return r.Seek(offset-r.cur, io.SeekCurrent, buffer)
	case io.SeekEnd:
		return 0, ErrSeekEnd
	case io.SeekCurrent:
		if offset <= 0 {
			r.cur += offset
			return r.cur, nil
		}
		if r.cur+offset <= r.edge {
			r.cur += offset
			return r.cur, nil
		}
		newCur := r.cur + offset
		if buffer {
			for r.cur < newCur {
				_, err := r.readByte(buffer)
				if err != nil {
					return r.cur, err
				}
			}
		} else {
			r.cur = newCur
			return r.cur, nil
		}
		return r.cur, nil
	default:
		return 0, ErrSeekWhence
	}
}
