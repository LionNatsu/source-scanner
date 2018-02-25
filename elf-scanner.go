package main

/*
#include <stdlib.h>
#include <string.h>
#include <elf.h>

void copy_elf_hdr(Elf64_Ehdr *ehdr, void *raw) {
    memcpy(ehdr, raw, sizeof(Elf64_Ehdr));
    free(raw);
}

void copy_sec_hdr(Elf64_Shdr *shdr, void *raw) {
    memcpy(shdr, raw, sizeof(Elf64_Shdr));
    free(raw);
}

void copy_dyntab_entry(Elf64_Dyn *dyntab, void *raw) {
    memcpy(dyntab, raw, sizeof(Elf64_Dyn));
    free(raw);
}
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"unsafe"
)

type ELFSOInfo struct {
	Type   int
	SoName string
	Needed []string
}

var (
	ErrNotAnELF            = errors.New("not an ELF file")
	ErrNotSupportedELFArch = errors.New("ELF architecture is not supported")
)

func analyseELF(input io.Reader, info *ELFSOInfo) error {
	var buffer = NewUDFR(input)
	var buf []byte

	// Read ELF header
	var ehdr C.Elf64_Ehdr
	{
		buf = make([]byte, C.sizeof_Elf64_Ehdr)
		n, _ := buffer.Read(buf)
		if n != len(buf) {
			return ErrNotAnELF
		}
		C.copy_elf_hdr(&ehdr, C.CBytes(buf))
		if err := VerifyELF(&ehdr); err != nil {
			return err
		}
	}
	info.Type = int(ehdr.e_type)

	if info.Type != C.ET_EXEC || info.Type != C.ET_DYN { // not an executable or dynamic object
		return nil
	}

	if ehdr.e_shnum == 0 { // no section
		return nil
	}

	// Read section headers
	var sections = make([]C.Elf64_Shdr, ehdr.e_shnum)
	{
		buffer.Seek(int64(ehdr.e_shoff), io.SeekStart, true)
		buf = make([]byte, C.sizeof_Elf64_Shdr*int64(ehdr.e_shnum))
		n, _ := buffer.Read(buf)
		if n != len(buf) {
			return ErrNotAnELF
		}
		for i := range sections {
			p := buf[C.sizeof_Elf64_Shdr*i:]
			C.copy_sec_hdr(&sections[i], C.CBytes(p))
		}
	}

	var dynamicSection, strTabSection, err = FindDynamicAndStringTableSection(sections)
	if err != nil {
		return errors.New("no string table linked to DYNAMIC")
	}

	if dynamicSection == nil || dynamicSection.sh_size == 0 { // static linked file
		return nil
	}

	var strTab = make([]byte, strTabSection.sh_size)
	var dynTab = make([]C.Elf64_Dyn, dynamicSection.sh_size/C.sizeof_Elf64_Dyn)
	strTabFunc := func() error {
		buffer.Seek(int64(strTabSection.sh_offset), io.SeekStart, false)
		if n, _ := buffer.Read(strTab); n != len(strTab) {
			return ErrNotAnELF
		}
		return nil
	}
	dynTabFunc := func() error {
		buffer.Seek(int64(dynamicSection.sh_offset), io.SeekStart, false)
		buf = make([]byte, C.sizeof_Elf64_Dyn*int64(dynamicSection.sh_size)/C.sizeof_Elf64_Dyn)
		n, _ := buffer.Read(buf)
		if n != len(buf) {
			return ErrNotAnELF
		}
		for i := range dynTab {
			C.copy_dyntab_entry(&dynTab[i], C.CBytes(buf[C.sizeof_Elf64_Dyn*i:]))
		}
		return nil
	}

	if strTabSection.sh_offset < dynamicSection.sh_offset {
		strTabFunc()
		dynTabFunc()
	} else {
		dynTabFunc()
		strTabFunc()
	}

	info.SoName, info.Needed = ReadDynamicTable(dynTab, strTab)

	return nil
}

func VerifyELF(ehdr *C.Elf64_Ehdr) error {
	var Ident = C.GoBytes(unsafe.Pointer(&ehdr.e_ident[0]), 16)
	if !bytes.HasPrefix(Ident, []byte(C.ELFMAG)) {
		return ErrNotAnELF
	}
	if ehdr.e_machine != C.EM_X86_64 {
		return ErrNotSupportedELFArch
	}
	return nil
}

func ReadDynamicTable(dynTab []C.Elf64_Dyn, strTab []byte) (SoName string, Needed []string) {
	for i := range dynTab {
		switch dynTab[i].d_tag {
		case C.DT_NEEDED:
			needed := StringFromTable(strTab, a2i(dynTab[i].d_un))
			Needed = append(Needed, needed)
		case C.DT_SONAME:
			soname := StringFromTable(strTab, a2i(dynTab[i].d_un))
			SoName = soname
		}
	}
	return
}

func FindDynamicAndStringTableSection(Sections []C.Elf64_Shdr) (DynamicSection, StrTabSection *C.Elf64_Shdr, err error) {
	for i := range Sections {
		if Sections[i].sh_type == C.SHT_DYNAMIC {
			DynamicSection = &Sections[i]
			StrTabSection = &Sections[Sections[i].sh_link]
			if StrTabSection.sh_type != C.SHT_STRTAB {
				err = errors.New("no STRTAB linked to DYNAMIC")
				return
			}
			break
		}
	}
	return
}

func a2i(a [8]byte) uint64 {
	return binary.LittleEndian.Uint64(a[:])
}

func StringFromTable(strTab []byte, begin uint64) string {
	var end int
	for end = int(begin); end != len(strTab); end++ {
		if strTab[end] == 0 { // find '\0' character
			break
		}
	}
	return string(strTab[int(begin):end])
}
