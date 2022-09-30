package main

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

const (
	ShutdownPort = ":5003"
)

func runShutdownServer() error {
	log.Info("Starting Shutdown server...")

	shutdownMux := http.NewServeMux()
	shutdownMux.HandleFunc("/shutdown", handleShutdown)

	// go func() {
	log.Infof("Shutdown server is listening on %s\n", ShutdownPort)
	if err := http.ListenAndServe(ShutdownPort, shutdownMux); err != nil {
		log.Fatalf("Failed to serve %s\n", err.Error())
	}
	// }()

	return nil
}

func handleShutdown(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Shutdown Server OK"))
}
