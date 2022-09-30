package main

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

const (
	ChallengePort = ":5002"
)

func runChallengeServer() error {
	log.Info("Starting Challenge server...")

	challengeMux := http.NewServeMux()
	challengeMux.HandleFunc("/", handleChallenge)

	go func() {
		log.Infof("Challenge server is listening on %s\n", ChallengePort)
		if err := http.ListenAndServe(ChallengePort, challengeMux); err != nil {
			log.Fatalf("Failed to serve %s\n", err.Error())
		}
	}()

	return nil
}

func handleChallenge(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Challenge Server OK"))
}
