package main

import (
	"database/sql"
	"log"
	"strings"
	"sync"

	_ "github.com/mattn/go-sqlite3"
	"path/filepath"
)

var DB *sql.DB
var lockWrite = &sync.Mutex{}

func dbInit(pwd, db string) error {
	if DB == nil {
		db, err := sql.Open("sqlite3", "file:"+filepath.Join(pwd, db+".db"))
		if err != nil {
			return err
		}
		DB = db
		_, err = DB.Exec(
			`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS repository (
  	filename	TEXT PRIMARY KEY,
	package	TEXT,
	version	TEXT,
	hash	TEXT,
	size	INTEGER,
	mtime	INTEGER
);
CREATE TABLE IF NOT EXISTS elf_depends (
	package	TEXT,
	version	TEXT,
	depends	TEXT,
	sover	TEXT
);
CREATE TABLE IF NOT EXISTS elf_provides (
	package	TEXT,
	version	TEXT,
	provides	TEXT,
	sover	TEXT
);
CREATE TABLE IF NOT EXISTS package_files (
	package	TEXT,
	version	TEXT,
	filename	TEXT,
	size	INTEGER,
	type	INTEGER
);
CREATE INDEX IF NOT EXISTS idx_elf_depends_pkg ON elf_depends (
	package,
	version
);
CREATE INDEX IF NOT EXISTS idx_elf_depends ON elf_depends (
	depends
);
CREATE INDEX IF NOT EXISTS idx_elf_provides_pkg ON elf_provides (
	package,
	version
);
CREATE INDEX IF NOT EXISTS idx_elf_provides ON elf_provides (
	provides
);
CREATE INDEX IF NOT EXISTS idx_package_files ON package_files (
	package,
	version
);
`)
		if err != nil {
			log.Fatalln(err)
		}
	}
	return nil
}

func dbExists(info *PackageInfo) (bool, error) {
	rows, err := DB.Query("SELECT * FROM repository WHERE filename=? AND mtime=?", info.Filename, info.Mtime)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	return rows.Next(), nil
}

func dbInsert(info *PackageInfo) error {
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	lockWrite.Lock()
	defer lockWrite.Unlock()
	{
		if _, err = tx.Exec(
			"INSERT OR REPLACE INTO repository VALUES(?,?,?,?,?,?)",
			info.Filename,
			info.Package,
			info.Version,
			info.SHA256,
			info.Size,
			info.Mtime,
		); err != nil {
			return err
		}

		if _, err = tx.Exec(
			"DELETE FROM elf_provides WHERE package=? AND version=?",
			info.Package,
			info.Version,
		); err != nil {
			return err
		}
		stmt1, err := tx.Prepare("INSERT INTO elf_provides VALUES(?,?,?,?)")
		if err != nil {
			return err
		}
		defer stmt1.Close()
		for _, provides := range info.Provides {
			name, sover := SplitSoName(provides)
			if _, err := stmt1.Exec(
				info.Package,
				info.Version,
				name,
				sover,
			); err != nil {
				return err
			}
		}

		if _, err = tx.Exec(
			"DELETE FROM elf_depends WHERE package=? AND version=?",
			info.Package,
			info.Version,
		); err != nil {
			return err
		}
		stmt2, err := tx.Prepare("INSERT INTO elf_depends VALUES(?,?,?,?)")
		if err != nil {
			return err
		}
		defer stmt2.Close()
		for _, depends := range info.Depends {
			name, sover := SplitSoName(depends)
			_, err := stmt2.Exec(
				info.Package,
				info.Version,
				name,
				sover,
			)
			if err != nil {
				return err
			}
		}

		if _, err = tx.Exec(
			"DELETE FROM package_files WHERE package=? AND version=?",
			info.Package,
			info.Version,
		); err != nil {
			return err
		}
		stmt3, err := tx.Prepare("INSERT INTO package_files VALUES(?,?,?,?,?)")
		if err != nil {
			return err
		}
		defer stmt3.Close()
		for _, file := range info.Contents {
			_, err := stmt3.Exec(
				info.Package,
				info.Version,
				file.Name,
				file.Size,
				file.Type,
			)
			if err != nil {
				return err
			}
		}
	}
	tx.Commit()
	return nil
}

func SplitSoName(soname string) (name, sover string) {
	a := strings.LastIndex(soname, ".so")
	if a == -1 {
		return soname, ""
	} else {
		return soname[:a+3], soname[a+3:]
	}
}
