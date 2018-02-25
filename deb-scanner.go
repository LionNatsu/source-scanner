package main

import (
	"archive/tar"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type FileInfo struct {
	Name string
	Size int64
	Type byte
}

type PackageInfo struct {
	Package  string
	Version  string
	Filename string
	Mtime    int64
	SHA256   string
	Deb822   [][]string

	Size     int64
	DataSize int64

	Provides []string
	Depends  []string
	Contents []*FileInfo
}

var NumCPU = runtime.NumCPU()
var goroutinePool = make(chan int, NumCPU)

var hashTotalSize int64
var hashCurrent int64

var decompressTotalSize int64
var decompressCurrent int64

var packagesTotal int64
var packagesCurrent int64
var filesCurrent int64
var elfsCurrent int64

var Packages []*PackageInfo

var goroutineWait sync.RWMutex

func progressBar(k int, name string, prev, current, total int64, interval int) {
	p := float64(current) / float64(total)
	fmt.Print("\u001b[0G\u001b[2K" + name + " [" + strings.Repeat("#", int(float64(k)*p)) + strings.Repeat(" ", int(float64(k)*(1-p))) + "] ")
	fmt.Printf("%0.3f%%, %.2f MB/s\n", 100*float64(current)/float64(total), float64(current-prev)/1024/1024/(float64(interval)/1000))
}

func scan() {
	fmt.Print("\n\n\n")
	filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(info.Name(), ".deb") {
			info := GetPackageInfo(path)
			if info == nil {
				return nil
			}
			Packages = append(Packages, info)
			hashTotalSize += info.Size
			decompressTotalSize += info.DataSize
			packagesTotal++
			fmt.Print("\u001b[A\u001b[A\u001b[A")
			fmt.Printf("\u001b[2KPackages: %d\n", packagesTotal)
			fmt.Printf("\u001b[2KTotal hash size: %.2f MB\n", float64(hashTotalSize)/1024/1024)
			fmt.Printf("\u001b[2KTotal decompress size: %.2f MB\n", float64(decompressTotalSize)/1024/1024)
		}
		return nil
	})
	fmt.Print("\n")
	go func() {
		const Duration = 500
		var prevHash, prevDec int64
		fmt.Print("\n\n\n")
		for {
			prevHash = hashCurrent
			prevDec = decompressCurrent

			time.Sleep(time.Millisecond * Duration)
			fmt.Print("\u001b[A\u001b[A\u001b[A")
			progressBar(60, "Hash      ", prevHash, hashCurrent, hashTotalSize, Duration)
			progressBar(60, "Decompress", prevDec, decompressCurrent, decompressTotalSize, Duration)
			fmt.Printf("\u001b[0G\u001b[2KPackages: %d / %d\tFiles: %d\tELF: %d\n",
				packagesCurrent,
				packagesTotal,
				filesCurrent,
				elfsCurrent,
			)
		}
	}()
	for index := range Packages {
		goroutinePool <- 1    // queue++
		goroutineWait.RLock() // "reader"++
		go func(index int) {
			DoPackage(Packages[index])
			Packages[index] = nil
		}(index)
	}
	goroutineWait.Lock() // Acquire "writer" lock: no "reader" -- no working goroutine
	goroutineWait.Unlock()
}

func DoPackage(info *PackageInfo) {
	defer goroutineWait.RUnlock() // "reader"--
	defer func() {
		<-goroutinePool // queue--
		atomic.AddInt64(&packagesCurrent, 1)
	}()

	if exists, err := dbExists(info); err != nil {
		log.Fatalln(info.Package, err)
		return
	} else if exists { // Jump
		atomic.AddInt64(&hashCurrent, info.Size)
		atomic.AddInt64(&decompressCurrent, info.DataSize)
		return
	}

	JobChecksum(info)

	f, _ := os.Open(info.Filename)
	defer f.Close()

	var arInfo, arReader = ArFind(f, "data.tar.")
	var dataFileReader = NewMeter(arReader, &decompressCurrent)

	dataReader := Decompress(arInfo.Name, dataFileReader)
	defer dataReader.Close()

	// Use map to ignore duplication fast
	var soname = make(map[string]bool, 20)
	var needed = make(map[string]bool, 100)

	var tarReader = tar.NewReader(dataReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Print(info.Package, " ", err, "\n\n\n\n")
			return
		}
		JobContentsUpdate(info, header)
		JobELFDependencyUpdate(soname, needed, header.Name, tarReader)
	}
	JobELFDependencyFinal(info, soname, needed)

	if err := dbInsert(info); err != nil {
		log.Fatalln(info.Package, err)
	}
}

func JobContentsUpdate(info *PackageInfo, header *tar.Header) {
	info.Contents = append(info.Contents, &FileInfo{Name: header.Name, Size: header.Size, Type: header.Typeflag})
	atomic.AddInt64(&filesCurrent, 1)
}

func JobELFDependencyUpdate(soname, needed map[string]bool, file string, reader io.Reader) {
	var soInfo ELFSOInfo
	err := analyseELF(reader, &soInfo)
	if err == nil {
		if soInfo.SoName != "" && InRPath(file) {
			soname[soInfo.SoName] = true
		}
		for _, soDep := range soInfo.Needed {
			needed[soDep] = true
		}
		atomic.AddInt64(&elfsCurrent, 1)
	}
}

func JobELFDependencyFinal(info *PackageInfo, soname, needed map[string]bool) {
	// Collect so file names
	for provides := range soname {
		info.Provides = append(info.Provides, provides)
	}
	// Collect so file dependencies (remove self-resolved dependencies)
DEPENDS:
	for depends := range needed {
		if _, exist := soname[depends]; exist { // short path
			continue DEPENDS
		}
		for provides := range soname {
			if MeetSoName(provides, depends) {
				continue DEPENDS
			}
		}
		info.Depends = append(info.Depends, depends)
	}
}

func JobChecksum(info *PackageInfo) {
	f, err := os.Open(info.Filename)
	if err != nil {
		log.Fatalln(err)
	}
	h := sha256.New()
	hashBlockSize := h.BlockSize()
	buffer := make([]byte, hashBlockSize*100)
	for {
		fileBlockSize, err := f.Read(buffer)
		if err == io.EOF {
			break
		}
		atomic.AddInt64(&hashCurrent, int64(fileBlockSize))
		h.Write(buffer[:fileBlockSize])
	}
	f.Close()
	SHA256 := fmt.Sprintf("%2x", h.Sum(nil))
	info.SHA256 = SHA256
}

var fieldRegex = regexp.MustCompile(`(?P<key>[^: \t\n\r\f\v]+)\s*:\s*(?P<value>.*)`)

func GetPackageInfo(deb string) *PackageInfo {
	f, err := os.Open(deb)
	if err != nil {
		log.Println(deb, err)
		return nil
	}
	defer f.Close()

	arInfo, arReader := ArFind(f, "control.tar.")
	if arReader == nil {
		log.Print(deb, " deb corrupted\n\n\n\n")
		return nil
	}
	dataReader := Decompress(arInfo.Name, arReader)
	defer dataReader.Close()
	_, tarReader := TarFind(dataReader, "./control")
	out, _ := ioutil.ReadAll(tarReader)
	control := string(out)
	var dict [][]string
	result := fieldRegex.FindAllStringSubmatch(control, 20)
	for _, field := range result {
		dict = append(dict, field[1:])
	}

	st, _ := f.Stat()
	size := st.Size()
	dataInfo, _ := ArFind(f, "data.tar.")
	pi := &PackageInfo{
		Package:  Deb822Find(dict, "Package"),
		Version:  Deb822Find(dict, "Version"),
		Filename: deb,
		Mtime:    st.ModTime().Unix(),
		Deb822:   dict,
		Size:     size,
		DataSize: dataInfo.Size,
	}
	return pi
}

func Deb822Find(dict [][]string, key string) string {
	for _, v := range dict {
		if v[0] == key {
			return v[1]
		}
	}
	panic(key)
}

func MeetSoName(have, want string) bool {
	return strings.HasPrefix(have+".", want+".")
}

func InRPath(file string) bool {
	var prefixes = []string{
		"./lib/",
		"./lib64/",
		"./usr/lib/",
		"./usr/lib64/",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(file, prefix) {
			return true
		}
	}
	return false
}
