package main

import (
	"database/sql"
	"log"
	"strings"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB
var lockInit = &sync.Mutex{}

func dbInit() error {
	lockInit.Lock()
	defer lockInit.Unlock()
	if DB == nil {
		db, err := sql.Open("sqlite3", "file:somap.db")
		if err != nil {
			return err
		}
		DB = db
	}
	return nil
}

func dbExists(info *PackageSOInfo) (bool, error) {
	if err := dbInit(); err != nil {
		return false, err
	}

	rows, err := DB.Query("SELECT * FROM dpkg_contents WHERE package=? AND version=?", info.Package, info.Version)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	return rows.Next(), nil
}

func dbInsert(info *PackageSOInfo) error {
	log.Println("insert...")
	defer log.Println("insert...OK")

	if err := dbInit(); err != nil {
		return err
	}

	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	stmt1, err := tx.Prepare("INSERT INTO so_provides(package, version, provides, sover) VALUES(?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt1.Close()
	for _, provides := range info.Provides {
		name, sover := SplitSoName(provides)
		_, err := stmt1.Exec(info.Package, info.Version, name, sover)
		if err != nil {
			return err
		}
	}
	stmt2, err := tx.Prepare("INSERT INTO so_depends(package, version, depends, sover) VALUES(?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt2.Close()
	for _, depends := range info.Depends {
		name, sover := SplitSoName(depends)
		_, err := stmt2.Exec(info.Package, info.Version, name, sover)
		if err != nil {
			return err
		}
	}
	stmt3, err := tx.Prepare("INSERT INTO dpkg_contents(package, version, content) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt3.Close()
	for _, contents := range info.Contents {
		_, err := stmt3.Exec(info.Package, info.Version, contents)
		if err != nil {
			return err
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
