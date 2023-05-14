package main

import (
	"bytes"
	"fmt"

	hs "github.com/flier/gohs/hyperscan"
)

var (
	// BufferSize int = 1e7 //10M
	initSize     int  = 1e4              // 10KB
	maxSize      int  = 1024 * 1024 * 10 // 10MB
	RESET        uint = 0x1
	RESETANDSCAN uint = 0x2
	SCAN         uint = 0x4
	SCANANDRESET uint = 0x8
	SKIP         uint = 0x10
)

type StreamBuffer struct {
	buf bytes.Buffer
	//bufferChan chan bytes.Buffer
	stream    *hs.Stream
	db        *hs.StreamDatabase
	s         *hs.Scratch
	match     func(id uint, from, to uint64, flags uint, ctx interface{}) error
	cl        int
	headerLen int
	flags     hs.ScanFlag
}

func NewStreamBuffer(flags hs.ScanFlag, db *hs.StreamDatabase, s *hs.Scratch, match func(id uint, from, to uint64, flags uint, ctx interface{}) error) *StreamBuffer {
	byteSlize := make([]byte, 0)
	byteBuffer := bytes.NewBuffer(byteSlize)
	streamBuffer := new(StreamBuffer)
	streamBuffer.buf = *byteBuffer
	//streamBuffer.bufferChan = make(chan bytes.Buffer)
	streamBuffer.flags = flags
	stream, err := (*db).Open(flags, s, match, &streamBuffer.buf)
	if err != nil {
		panic(err)
	}
	streamBuffer.stream = &stream

	streamBuffer.db = db
	streamBuffer.s = s
	streamBuffer.match = match
	return streamBuffer
}

func (s *StreamBuffer) Handle(buf []byte, l int) {
	// Open a new stream when:
	// 1.there is a new HTTP request
	// 2.len exceeds Content-Length
	// 3.size of the buffer larger than maxSize
	// Otherwise, do scan on the existing stream
	indexs := extractHttp(buf)
	if len(indexs) <= 0 {
		indexs = append(indexs, 0)
	}
	for _, i := range indexs {
		bbuf := buf[i:]
		host, cl, headerLen, isResponse := analyzeHttp(string(bbuf))
		next := s.resolve(l, host, cl, headerLen, isResponse)
		switch next {
		case SKIP:
			break
		case SCAN:
			s.buf.Write(bbuf)
			err := (*s.stream).Scan(bbuf)
			if err != nil {
				fmt.Printf("Scan error %s", err.Error())
			}
		case RESET:
			s.Reset(cl)
		case SCANANDRESET:
			s.buf.Write(bbuf)
			err := (*s.stream).Scan(bbuf)
			if err != nil {
				fmt.Printf("Scan error %s", err.Error())
			}
			s.Reset(cl)
		case RESETANDSCAN:
			s.Reset(cl)
			s.buf.Write(bbuf)
			err := (*s.stream).Scan(bbuf)
			if err != nil {
				fmt.Printf("Scan error %s", err.Error())
			}
		default:
			break
		}
		break
	}

}
func (s *StreamBuffer) resolve(len int, host string, cl int64, headerLen int, isResponse bool) uint {
	if isResponse {
		return SKIP
	}
	if len <= 1 {
		return SKIP
	}
	fmt.Printf("recv data,len:%d ", len)
	if cl > 0 {
		// new request
		fmt.Printf("CL:%d ", cl)
		if host != "" {
			fmt.Printf("Host:%s", host)
		}
		fmt.Println()
		s.cl = int(cl)
		s.headerLen = headerLen
		return RESETANDSCAN
	}
	if host != "" {
		// new request
		fmt.Printf("HOST:%s ", host)
		fmt.Println()
		s.headerLen = headerLen
		return RESETANDSCAN
	}
	if len+s.buf.Len() > maxSize {
		// size of the buffer larger than maxSize
		fmt.Printf("Buffer too large!(%d>%d) ", len+s.buf.Len(), maxSize)
		fmt.Println()
		return RESET
	}
	if s.cl > 0 {
		cur := len + s.buf.Len() - s.headerLen
		if cur > int(s.cl) {
			// size of the buffer larger than CL
			fmt.Printf("CL exceeds!(%d>%d) ", cur, int(s.cl))
			fmt.Println()
			return SCANANDRESET
		}
	}
	fmt.Printf("Not HTTP\n")
	return SCAN

}
func (s *StreamBuffer) Reset(cl int64) {
	//s.buf.Reset()
	byteSlize := make([]byte, 0)
	s.buf = *bytes.NewBuffer(byteSlize)
	(*(s.stream)).Close()
	m := hs.MatchHandler(s.match)
	stream, err := (*(s.db)).Open(s.flags, s.s, m, &s.buf)
	if err != nil {
		panic(err)
	}
	s.stream = &stream
	s.cl = int(cl)

}
