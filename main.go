package main

import (
	"log"
	"os"
	"os/signal"
)

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	var intCh = make(chan os.Signal, 1)
	signal.Notify(intCh, os.Interrupt)

	if len(os.Args) != 3 {
		log.Fatalln("not enough arguments")
	}

	go func() {
		<-intCh
		DB.Close()
		os.Exit(1)
	}()

	pwd, err := os.Getwd()
	if err != nil {
		log.Fatalln(err)
	}
	dbInit(pwd, os.Args[2])
	os.Chdir(os.Args[1])
	scan()
}
