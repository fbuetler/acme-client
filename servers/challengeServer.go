package servers

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

const (
	ChallengePort       = ":5002"
	ChallengePathPrefix = "/.well-known/acme-challenge/"
)

type Provision struct {
	Token      string
	Thumbprint string
}

func RunChallengeServer(ps []Provision) error {
	log.Info("Starting Challenge server...")
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHealth)

	for _, p := range ps {
		path := ChallengePathPrefix + p.Token
		mux.HandleFunc(path, handleChallenge(p.Thumbprint))
		log.WithField("Path", path).Debug("Published validation.")
	}

	go func() {
		log.Infof("Challenge server is listening on %s\n", ChallengePort)
		if err := http.ListenAndServe(ChallengePort, mux); err != nil {
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
