package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

type PackageSOInfo struct {
	Package  string   `json:"package"`
	Version  string   `json:"version"`
	Provides []string `json:"provides"`
	Depends  []string `json:"depends"`
	Contents []string `json:"contents"`
}

const WorkDir = "/tmp/soMapFiles"

var numCPU = runtime.NumCPU()
var goroutinePool = make(chan int, numCPU)
var clock int

func scan() {
	if len(os.Args) != 2 {
		log.Fatalln("not enough arguments")
	}
	filepath.Walk(os.Args[1], func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(info.Name(), ".deb") {
			clock++
			goroutinePool <- 1
			go DoPackage(WorkDir+strconv.Itoa(clock), path)
		}
		return nil
	})
}

func pushItem(ch chan<- string, workdir string, path string) {
	if path == "" {
		return
	}
	if info, err := os.Lstat(filepath.Join(workdir, path)); err != nil || info.IsDir() {
		return
	}
	ch <- path
}

func DoPackage(workdir string, deb string) {
	defer func() { <-goroutinePool }()
	exec.Command("rm", "-rf", workdir).Run()
	if err := os.Mkdir(workdir, 0777); err != nil {
		log.Fatalln(err)
	}
	defer os.RemoveAll(workdir)

	info := &PackageSOInfo{}

	var err error
	info.Package, info.Version, err = GetPackageInfo(deb)
	if err != nil {
		log.Println(deb, err)
		return
	}
	if exists, err := dbExists(info); err != nil {
		log.Println(deb, err)
		return
	} else if exists {
		log.Println(deb, "skipped")
		return
	}

	cmd := exec.Command("sh", "-c", "ar p "+deb+" data.tar.xz | tar -Jxv -C "+workdir)
	tarStdoutBuf, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr

	var tarStdout = bufio.NewReader(tarStdoutBuf)
	cmd.Start()

	var lastLine string
	var queue = make(chan string, 100)
	var cancelled = make(chan interface{})

	go func() {
		for {
			line, _, err := tarStdout.ReadLine()
			if err != nil {
				pushItem(queue, workdir, lastLine)
				if err != io.EOF {
					log.Fatalln(deb, err)
				}
				close(cancelled)
				return
			}
			pushItem(queue, workdir, lastLine)
			lastLine = string(line)
		}
	}()

	soname := make(map[string]bool, 50)
	needed := make(map[string]bool, 50)
WALK:
	for {
		select {
		case path := <-queue:
			if soinfo, err := DoELF(workdir, path); err == nil {
				if soinfo.SoName != "" && strings.HasPrefix(filepath.Join("/", path), "/usr/lib/") {
					soname[soinfo.SoName] = true
				}
				for _, sodep := range soinfo.Needed {
					needed[sodep] = true
				}
			}
			info.Contents = append(info.Contents, filepath.Clean(path))
			os.Remove(path)
		case <-cancelled:
			err := cmd.Wait()
			if err != nil {
				log.Println("tar", err)
			}
			break WALK
		}
	}
	for provides := range soname {
		info.Provides = append(info.Provides, provides)
	}
DEPENDS:
	for depends := range needed {
		for provides := range soname {
			if MeetSoName(provides, depends) {
				continue DEPENDS
			}
		}
		info.Depends = append(info.Depends, depends)
	}
	sort.Strings(info.Provides)
	sort.Strings(info.Depends)
	a, _ := json.MarshalIndent(info, "", "\t")
	fmt.Print(string(a))
	if err := dbInsert(info); err != nil {
		log.Println(deb, err)
	}
}

var pkgRe = regexp.MustCompile(`Package: (\S+)`)
var verRe = regexp.MustCompile(`Version: (\S+)`)

func GetPackageInfo(deb string) (pkg, ver string, err error) {
	cmd := exec.Command("sh", "-c", "ar p "+deb+" control.tar.gz | tar -xz ./control -O")
	output, _ := cmd.Output()
	control := string(output)
	defer func() {
		if p := recover(); p != nil {
			err = errors.New("cannot get package info")
		}
	}()
	pkg = pkgRe.FindAllStringSubmatch(control, -1)[0][1]
	ver = verRe.FindAllStringSubmatch(control, -1)[0][1]
	return
}

func MeetSoName(have, want string) bool {
	return strings.HasPrefix(have+".", want+".")
}
