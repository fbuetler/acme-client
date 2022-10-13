package servers

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

const (
	ShutdownPort = ":5003"
)

func RunShutdownServer(closeDNSServer, closeCertServer, closeChalServer chan struct{}) error {
	l := log.WithField("component", "shutdown server")

	l.Info("Starting Shutdown server...")

	close := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/shutdown", handleShutdown(l, close, closeDNSServer, closeCertServer, closeChalServer))

	srv := http.Server{
		Addr:    ShutdownPort,
		Handler: mux,
	}

	go func() {
		<-close
		l.Info("Received shutdown signal. Terminating...")
		srv.Close()
	}()

	l.Infof("Shutdown server is listening on %s\n", ShutdownPort)
	if err := srv.ListenAndServe(); err != nil {
		l.Errorf("Failed to serve %s\n", err.Error())
	}

	return nil
}

func handleShutdown(l *log.Entry, closeShutdownServer, closeDNSServer, closeCertServer, closeChalServer chan struct{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Shutdown Server OK"))

		l.Debug("Sending shutdown signal to certificate server.")
		closeCertServer <- struct{}{}

		l.Debug("Sending shutdown signal to challenge server.")
		closeChalServer <- struct{}{}

		l.Debug("Sending shutdown signal to DNS server.")
		closeDNSServer <- struct{}{}

		l.Debug("Sending shutdown signal to myself.")
		closeShutdownServer <- struct{}{}
	}
}
