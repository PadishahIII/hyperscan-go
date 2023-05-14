package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"syscall"

	hs "github.com/flier/gohs/hyperscan"
)

// Record matching text
//type Match struct {
//	from uint64
//	to   uint64
//}

var (
	//matches []Match
	PIPENUM   int               = 2
	JpgHeader []byte            = []byte{0xff, 0xd8, 0xff}
	PngHeader []byte            = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	GifHeader []byte            = []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}
	From      map[string]uint64 = map[string]uint64{
		"jpg": 0,
		"png": 0,
		"gif": 0,
	}
	To map[string]uint64 = map[string]uint64{
		"jpg": 0,
		"png": 0,
		"gif": 0,
	}
	DEBUG bool = true
)

type MatchContextInterface interface {
	GetData() []byte
}

type MatchContext struct {
	ctx context.Context
}

func (mctx *MatchContext) GetData() []byte {
	return mctx.ctx.Value("data").([]byte)
}

func extractHttp(buf []byte) (indexs []int) {
	prefixList := []string{"GET", "POST", "OPTION", "PUT", "DELETE", "HEAD"}
	for _, i := range prefixList {
		if a := strings.Index(string(buf), i); a >= 0 {
			indexs = append(indexs, a)
		}
	}
	return indexs
}

func analyzeHttp(str string) (host string, cl int64, headerLen int, isResponse bool) {
	host = ""
	cl = 0
	headerLen = 0
	isResponse = false
	if strings.HasPrefix(str, "HTTP/1.") {
		isResponse = true
		return host, cl, headerLen, isResponse
	}
	prefixList := []string{"GET", "POST", "OPTION", "PUT", "DELETE", "HEAD"}
	f := false
	for _, i := range prefixList {
		if strings.HasPrefix(str, i) {
			f = true
			break
		}
	}
	if !f {
		return host, cl, headerLen, isResponse
	}
	requestReader := bufio.NewReader(strings.NewReader(str))
	request, err := http.ReadRequest(requestReader)
	headerLen = strings.Index(str, "\r\n\r\n")
	if headerLen < 0 {
		headerLen = len(str)
	} else {
		headerLen += 4
	}
	if err != nil {
		fmt.Println(err.Error())
		return host, cl, headerLen, isResponse
	}
	host = request.Host
	cl = request.ContentLength

	return host, cl, headerLen, isResponse
}

//func processPkt(buf []byte, len int, streamBuffer *StreamBuffer) {
//	streamBuffer.Handle(buf, len)
//}

func match(id uint, from, to uint64, flags uint, ctx interface{}) error {
	buf := ctx.(*bytes.Buffer)
	value := buf.Bytes()
	if len(value) <= 0 {
		fmt.Printf("Error:Empty match")
		return nil
	}
	if id == 101 {
		fmt.Printf("JPEG Header detected\n")
		From["jpg"] = from
		return nil
	}
	if id == 111 {
		fmt.Printf("PNG Header detected\n")
		From["png"] = from
		return nil
	}
	if id == 121 {
		fmt.Printf("GIF Header detected\n")
		From["gif"] = from
		return nil
	}
	if id == 102 {
		//fmt.Printf("JPEG Tail detected\n")
		To["jpg"] = to
		if DEBUG {
			ff := From["jpg"]
			headerEnd := int(ff) + len(JpgHeader)
			if headerEnd >= 0 && headerEnd < len(value) {
				if bytes.Equal(JpgHeader, value[int(ff):headerEnd]) {
					if ff <= to && to < uint64(len(value)) {
						fmt.Printf("JPEG detected, len=%d\n", (to - ff))
						f, err := os.Create("tmp.jpg")
						if err != nil {
							fmt.Println(err.Error())
						}
						defer f.Close()
						f.Write(value[ff:to])
						return nil
					}
				}
			}

		}
		return nil
	}
	if id == 112 {
		//fmt.Printf("PNG Tail detected\n")
		To["png"] = to
		if DEBUG {
			ff := From["png"]
			headerEnd := int(ff) + len(PngHeader)
			if headerEnd >= 0 && headerEnd < len(value) {
				if bytes.Equal(PngHeader, value[int(ff):headerEnd]) {
					if ff <= to && to < uint64(len(value)) {
						fmt.Printf("PNG detected, len=%d\n", (to - ff))
						f, err := os.Create("tmp.png")
						if err != nil {
							fmt.Println(err.Error())
						}
						defer f.Close()
						f.Write(value[ff:to])
						return nil
					}
				}
			}

		}
		return nil
	}
	if id == 122 {
		To["gif"] = to
		if DEBUG {
			ff := From["gif"]
			headerEnd := int(ff) + len(GifHeader)
			if headerEnd >= 0 && headerEnd < len(value) {
				if bytes.Equal(GifHeader, value[int(ff):headerEnd]) {
					if ff <= to && to < uint64(len(value)) {
						//fmt.Printf("GIF Tail detected\n")
						fmt.Printf("GIF detected, len=%d\n", (to - ff))
						f, err := os.Create("tmp.gif")
						if err != nil {
							fmt.Println(err.Error())
						}
						defer f.Close()
						f.Write(value[ff:to])
						return nil
					}
				}
			}

		}
		return nil
	}

	if from <= to {
		fmt.Printf("reg id:%d from %d to %d :\n%s \n %s \n", id, from, to, string(value[from:to]), "*****************************")
	}
	return nil
}

func main() { //nolint:funlen
	if len(os.Args) != 2 {
		panic("Please assign a pattern file")
	}
	http := false
	https := true
	patternFileStr := os.Args[1]
	if _, err := os.Stat(patternFileStr); err != nil {
		fmt.Printf("%s not exists", patternFileStr)
		os.Exit(1)
	}
	fmt.Printf("Pattern File: %s", patternFileStr)
	patternFile, err := os.Open(patternFileStr)
	if err != nil {
		panic(err)
	}
	defer patternFile.Close()

	leftMostFlag, _ := hs.ParseCompileFlag("L")
	patterns, err := hs.ParsePatterns(patternFile)
	if err != nil {
		panic(err)
	}
	telPattern := hs.NewPattern(`300:/1(3\d|4[5-9]|5[0-35-9]|6[2567]|7[0-8]|8\d|9[0-35-9])\d{8}/`, leftMostFlag)
	if err != nil {
		panic(err)
	}
	jpgPattern := hs.NewPattern(`100:/\xFF\xD8\xFF.*?\xFF\xD9/`, leftMostFlag)
	if err != nil {
		panic(err)
	}
	jpgHeadPattern := hs.NewPattern(`101:/\xFF\xD8\xFF/`, leftMostFlag)

	if err != nil {
		panic(err)
	}
	jpgTailPattern := hs.NewPattern(`102:/\xFF\xD9/`, leftMostFlag)
	if err != nil {
		panic(err)
	}
	pngPattern := hs.NewPattern(`200:/\x89\x50\x4E\x47\x0D\x0A\x1A\x0A.*?\x49\x45\x4E\x44\xAE\x42\x60\x82/`, leftMostFlag)
	if err != nil {
		panic(err)
	}
	patterns = append(patterns, telPattern)
	patterns = append(patterns, jpgPattern)
	patterns = append(patterns, jpgHeadPattern)
	patterns = append(patterns, jpgTailPattern)
	patterns = append(patterns, pngPattern)

	// Create new stream database with pattern
	dbHttp, err := hs.NewStreamDatabase(patterns...)
	if err != nil {
		fmt.Println("create database failed,", err)
		return
	}
	dbHttps, err := hs.NewStreamDatabase(patterns...)
	//db.(hs.StreamScanner).Scan()
	if err != nil {
		fmt.Println("create database failed,", err)
		return
	}
	defer dbHttp.Close()
	defer dbHttps.Close()

	// Create new scratch for scanning
	scratchHttp, err := hs.NewScratch(dbHttps)
	if err != nil {
		fmt.Println("create scratch failed,", err)
		return
	}
	scratchHttps, err := hs.NewScratch(dbHttps)
	if err != nil {
		fmt.Println("create scratch failed,", err)
		return
	}

	defer func() {
		_ = scratchHttp.Free()
		_ = scratchHttps.Free()
	}()

	//handler := hs.MatchHandler(match)
	streamBufferHttp := NewStreamBuffer(0, &dbHttp, scratchHttp, match)
	streamBufferHttps := NewStreamBuffer(0, &dbHttps, scratchHttps, match)

	// Open fifo
	//fifopath, b := os.LookupEnv("FIFOPATH")
	//if !b || fifopath == "" {
	//	fmt.Printf("Error: env FIFOPATH not exists. Exiting...")
	//	os.Exit(1)
	//}
	//fifonids, b := os.LookupEnv("FIFONIDS")
	//if !b || fifonids == "" {
	//	fmt.Printf("Error: env FIFONIDS not exists. Exiting...")
	//	os.Exit(1)
	//}
	fifopath := "/tmp/fifoHttps"
	fifonids := "/tmp/fifoHttp"
	//fifoList := []string{fifopath, fifonids}
	fifoList := []string{fifopath, fifonids}
	fifoHandlers := [2]*os.File{nil, nil}
	fmt.Printf("\nFifo config...\necapture fifo: %s\nnids fifo: %s\n\n", fifopath, fifonids)
	fmt.Printf("Open fifo...\n")
	for i := 0; i < PIPENUM; i++ {
		if _, err := os.Stat(fifoList[i]); err != nil {
			fmt.Printf("fifo %s not exists. Creating...\n", fifoList[i])
			err := syscall.Mkfifo(fifoList[i], 0666)
			if err != nil {
				fmt.Printf("mkfifo err:%s:%s", fifoList[i], err.Error())
				continue
			}
		} else {
			fmt.Printf("fifo %s exists\n", fifoList[i])
		}
		if i == 0 && !https {
			continue
		}
		if i == 1 && !http {
			continue
		}
		fmt.Printf("Opening fifo %s ... \n", fifoList[i])
		fifoHandler, err := os.OpenFile(fifoList[i], os.O_RDONLY, os.ModeNamedPipe)
		if err != nil {
			fmt.Printf("Open fifo %s failed!(%v) Passing...\n", fifoList[i], err)
			continue
		}
		fifoHandlers[i] = fifoHandler
	}
	defer func() {
		for _, i := range fifoHandlers {
			i.Close()
		}
	}()
	fmt.Printf("\nOpen fifos finish:\n")

	fifoNum := 0
	for i := 0; i < PIPENUM; i++ {
		if fifoHandlers[i] == nil {
			fmt.Printf("Close --- %s\n", fifoList[i])
		} else {
			fmt.Printf("Open --- %s\n", fifoList[i])
			fifoNum += 1
		}
	}
	if fifoNum <= 0 {
		fmt.Printf("No fifo opened. Exiting...\n")
		os.Exit(1)
	}
	fmt.Printf("\nRecving Data... \n\n")

	dataHttp := make(chan []byte)
	dataHttps := make(chan []byte)
	for i, fifo := range fifoHandlers {
		if fifo == nil {
			continue
		}
		if i == 0 {
			go func(f *os.File, ch chan<- []byte) {
				d := make([]byte, 65535)
				for {
					n, err := f.Read(d)
					if err != nil {
						//panic(err)
						fmt.Printf("err: %v\n", err)
						break
					}
					dCopy := make([]byte, n)
					copy(dCopy, d[:n])
					ch <- dCopy
				}
			}(fifo, dataHttps)
		} else {
			go func(f *os.File, ch chan<- []byte) {
				d := make([]byte, 65535)
				for {
					n, err := f.Read(d)
					if err != nil {
						//panic(err)
						fmt.Printf("err: %v\n", err)
						break
					}
					dCopy := make([]byte, n)
					copy(dCopy, d[:n])
					ch <- dCopy
				}
			}(fifo, dataHttp)
		}
	}
	for {
		select {
		case buf := <-dataHttp:
			streamBufferHttp.Handle(buf, len(buf))
		case buf := <-dataHttps:
			streamBufferHttps.Handle(buf, len(buf))
		}
	}

}
