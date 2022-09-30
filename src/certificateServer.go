package main

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

const (
	CertificatePort = ":5001"
)

func runCertificateServer() error {
	log.Info("Starting Certificate server...")

	certificateMux := http.NewServeMux()
	certificateMux.HandleFunc("/", handleCertificate)

	go func() {
		log.Infof("Certificate server is listening on %s\n", CertificatePort)
		if err := http.ListenAndServe(CertificatePort, certificateMux); err != nil {
			log.Fatalf("Failed to serve %s\n", err.Error())
		}
	}()

	return nil
}

func handleCertificate(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Certificate Server OK"))
}
