package main

import (
	"net/http"
	"fmt"
	"log"
	"encoding/json"
)

func mainHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	jsonData, err := json.Marshal(pushData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Write(jsonData)
}

func run() {
	http.Handle("/web/css/", http.StripPrefix("/web/css/", http.FileServer(http.Dir("web/css"))))
	fmt.Println("started")
	http.HandleFunc("/data", dataHandler)
	http.HandleFunc("/", mainHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}