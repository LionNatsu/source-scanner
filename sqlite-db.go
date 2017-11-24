package main

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
	"sync"
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

	rows, err := DB.Query("SELECT * FROM contents WHERE package=? AND version=?", info.Package, info.Version)
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
	stmt1, _ := tx.Prepare("INSERT INTO so_provides(package, version, provides) VALUES(?, ?, ?)")
	defer stmt1.Close()
	for _, provides := range info.Provides {
		_, err := stmt1.Exec(info.Package, info.Version, provides)
		if err != nil {
			return err
		}
	}
	stmt2, _ := tx.Prepare("INSERT INTO so_depends(package, version, depends) VALUES(?, ?, ?)")
	defer stmt2.Close()
	for _, depends := range info.Depends {
		_, err := stmt2.Exec(info.Package, info.Version, depends)
		if err != nil {
			return err
		}
	}
	stmt3, _ := tx.Prepare("INSERT INTO contents(package, version, contents) VALUES(?, ?, ?)")
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
