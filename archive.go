package main

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"io/ioutil"
	"log"
	"os/exec"
	"strconv"
	"strings"
)

type ArFileDescriptor struct {
	Name      string
	Timestamp int64
	Owner     int
	Group     int
	Mode      uint32
	Size      int64
}

func ArFind(input io.ReadSeeker, file string) (*ArFileDescriptor, io.Reader) {
	input.Seek(0, io.SeekStart)
	buf := make([]byte, 16)
	input.Read(buf[:8])
	if string(buf[:8]) != "!<arch>\n" {
		log.Fatalln("corrupted format")
	}
	for {
		var fd ArFileDescriptor
		_, err := input.Read(buf[:16])
		if err == io.EOF {
			break
		}
		fd.Name = strings.TrimSpace(string(buf[:16]))

		input.Read(buf[:12])
		fd.Timestamp, _ = strconv.ParseInt(strings.TrimSpace(string(buf[:12])), 10, 64)

		input.Read(buf[:6])
		fd.Owner, _ = strconv.Atoi(strings.TrimSpace(string(buf[:6])))

		input.Read(buf[:6])
		fd.Group, _ = strconv.Atoi(strings.TrimSpace(string(buf[:6])))

		input.Read(buf[:8])
		t, _ := strconv.ParseUint(strings.TrimSpace(string(buf[:8])), 8, 32)
		fd.Mode = uint32(t)

		input.Read(buf[:10])
		fd.Size, _ = strconv.ParseInt(strings.TrimSpace(string(buf[:10])), 10, 64)

		input.Read(buf[:2])
		if string(buf[:2]) != "`\n" {
			return nil, nil
		}
		if strings.HasPrefix(fd.Name, file) {
			return &fd, input
		}
		offset := fd.Size
		offset += offset & 1
		input.Seek(offset, io.SeekCurrent)
	}
	return nil, nil
}

func TarFind(input io.Reader, file string) (*tar.Header, io.Reader) {
	tarReader := tar.NewReader(input)
	for {
		h, err := tarReader.Next()
		if err == io.EOF {
			return nil, nil
		}
		if h.Name == file {
			return h, tarReader
		}
	}
}

func Decompress(file string, input io.Reader) io.ReadCloser {
	if strings.HasSuffix(file, ".gz") {
		return ioutil.NopCloser(GzDecompress(input))
	}
	if strings.HasSuffix(file, ".xz") {
		return XzDecompress(input)
	}
	return nil
}

func GzDecompress(input io.Reader) io.Reader {
	r, err := gzip.NewReader(input)
	if err != nil {
		log.Fatalln(err)
	}
	return r
}

func XzDecompress(input io.Reader) io.ReadCloser {
	var xzReader, w = io.Pipe()

	var xzCmd = exec.Command("xz", "-d")
	xzCmd.Stdin = input
	xzCmd.Stdout = w

	err := xzCmd.Start()
	if err != nil {
		log.Fatalln(err)
	}
	go func() {
		xzCmd.Wait()
		w.Close()
	}()
	return xzReader
}
