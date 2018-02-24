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

	if len(os.Args) != 2 {
		log.Fatalln("not enough arguments")
	}

	go func() {
		<-intCh
		DB.Close()
		os.Exit(1)
	}()

	dbInit()
	WorkDir = os.Args[1]
	scan()
}
