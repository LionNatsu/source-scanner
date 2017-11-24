package main

/*
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

FILE *open_file(const char *path) {
    return fopen(path, "rb");
}

void close_file(FILE *fp) {
    fclose(fp);
}

void seek_file(FILE *fp, Elf64_Off pos) {
    fseek(fp, pos, SEEK_SET);
}

void read_elf_hdr(FILE *fp, Elf64_Ehdr *ehdr) {
    fread(ehdr, sizeof(Elf64_Ehdr), 1, fp);
}

void read_sec_hdr(FILE *fp, Elf64_Shdr *shdr) {
    fread(shdr, sizeof(Elf64_Shdr), 1, fp);
}

void read_dyntab_entry(FILE *fp, Elf64_Dyn *dynsym) {
    fread(dynsym, sizeof(Elf64_Dyn), 1, fp);
}

char *read_string_table(FILE *fp, const Elf64_Shdr *shdr) {
    fseek(fp, shdr->sh_offset, SEEK_SET);
    char *buffer = malloc(shdr->sh_size);
    fread(buffer, shdr->sh_size, 1, fp);
    return buffer;
}

*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"path/filepath"
	"unsafe"
)

type ELFSOInfo struct {
	Type   int
	SoName string
	Needed []string
}

func DoELF(workdir string, path string) (*ELFSOInfo, error) {
	pathC := C.CString(filepath.Join(workdir, path))
	defer C.free(unsafe.Pointer(pathC))

	fp := C.open_file(pathC)
	if fp == nil {
		return nil, errors.New("cannot open file")
	}
	defer C.close_file(fp)

	var ehdr = new(C.Elf64_Ehdr)
	C.read_elf_hdr(fp, ehdr)

	var e_ident = C.GoBytes(unsafe.Pointer(&ehdr.e_ident[0]), 16)
	if !bytes.HasPrefix(e_ident, []byte(C.ELFMAG)) {
		return nil, errors.New("not an ELF file")
	}

	if ehdr.e_machine != C.EM_X86_64 {
		return nil, errors.New("not an AMD x86-64 architecture ELF file")
	}

	ret := &ELFSOInfo{}
	ret.Type = int(ehdr.e_type)

	C.seek_file(fp, ehdr.e_shoff)
	var shdr = make([]C.Elf64_Shdr, ehdr.e_shnum)

	for i := range shdr {
		C.read_sec_hdr(fp, &shdr[i])
	}

	var dynamic_section, strtab_section C.Elf64_Shdr

	for i := range shdr {
		if shdr[i].sh_type == C.SHT_DYNAMIC {
			dynamic_section = shdr[i]
			strtab_section = shdr[shdr[i].sh_link]
			if strtab_section.sh_type != C.SHT_STRTAB {
				return nil, errors.New("no STRTAB linked to DYNAMIC")
			}
			break
		}
	}

	var strtab = C.read_string_table(fp, &strtab_section)
	defer C.free(unsafe.Pointer(strtab))

	var dynamic = make([]C.Elf64_Dyn, dynamic_section.sh_size/C.sizeof_Elf64_Dyn)
	C.seek_file(fp, dynamic_section.sh_offset)
	for i := range dynamic {
		C.read_dyntab_entry(fp, &dynamic[i])
	}

	for i := range dynamic {
		switch dynamic[i].d_tag {
		case C.DT_NULL:
		case C.DT_NEEDED:
			needed := string_from_table(strtab, a2i(dynamic[i].d_un))
			ret.Needed = append(ret.Needed, needed)
		case C.DT_SONAME:
			soname := string_from_table(strtab, a2i(dynamic[i].d_un))
			ret.SoName = soname
		}
	}
	return ret, nil
}

func a2i(a [8]byte) uint64 {
	return binary.LittleEndian.Uint64(a[:])
}

func string_from_table(strtab *C.char, i uint64) string {
	base := uintptr(unsafe.Pointer(strtab))
	delta := uintptr(i)
	pointer := unsafe.Pointer(base + delta)
	return C.GoString((*C.char)(pointer))
}
