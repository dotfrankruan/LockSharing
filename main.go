package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("addr", ":11371", "HTTP listen address")
	dbPath := flag.String("db", "db.sqlite3", "SQLite database path")
	flag.Parse()

	db, err := OpenDB(*dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	srv := NewServer(db)
	fmt.Printf("LockSharing keyserver listening on %s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, srv))
}
