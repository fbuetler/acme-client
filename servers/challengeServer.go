package servers

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

const (
	ChallengePort       = ":5002"
	ChallengePathPrefix = "/.well-known/acme-challenge/"
)

func RunChallengeServer(token, keyThumbprint string) error {
	log.Info("Starting Challenge server...")

	challengePath := ChallengePathPrefix + token

	challengeMux := http.NewServeMux()
	challengeMux.HandleFunc("/", handleHealth)
	challengeMux.HandleFunc(challengePath, handleChallenge(keyThumbprint))
	log.WithField("Path", challengePath).Debug("Published validation.")

	go func() {
		log.Infof("Challenge server is listening on %s\n", ChallengePort)
		if err := http.ListenAndServe(ChallengePort, challengeMux); err != nil {
			log.Fatalf("Failed to serve %s\n", err.Error())
		}
	}()

	return nil
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Challenger Server OK"))

	log.Info(("Answered health request."))
}

func handleChallenge(keyThumbprint string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte(keyThumbprint))

		log.Info("Answered challenge request.")
	}
}
