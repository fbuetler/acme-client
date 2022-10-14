package servers

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

const (
	challengePort       = ":5002"
	challengePathPrefix = "/.well-known/acme-challenge/"
)

type HTTPProvision struct {
	Token      string
	Thumbprint string
}

func RunChallengeServer(close chan struct{}, ps []HTTPProvision) error {
	l := log.WithField("component", "challenge server")

	l.Info("Starting Challenge server...")
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHealth(l))

	for _, p := range ps {
		path := challengePathPrefix + p.Token
		mux.HandleFunc(path, handleChallenge(l, p.Thumbprint))
		l.WithField("Path", path).Debug("Published validation.")
	}

	srv := &http.Server{Addr: challengePort, Handler: mux}

	go func() {
		l.Infof("Challenge server is listening on %s\n", challengePort)
		if err := srv.ListenAndServe(); err != nil {
			l.Errorf("Failed to serve %s\n", err.Error())
		}
	}()

	go func() {
		<-close
		l.Info("Received shutdown signal. Terminating...")
		srv.Close()
	}()

	return nil
}

func handleHealth(l *log.Entry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Challenger Server OK"))

		l.Info(("Answered health request."))
	}
}

func handleChallenge(l *log.Entry, keyThumbprint string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte(keyThumbprint))

		l.Info("Answered challenge request.")
	}
}
