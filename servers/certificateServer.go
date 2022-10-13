package servers

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"

	log "github.com/sirupsen/logrus"
)

const (
	certificatePort = ":5001"
)

func RunCertificateServer(close chan struct{}, cert []byte, certKey *rsa.PrivateKey) error {
	l := log.WithField("component", "certificate server")

	l.Info("Starting Certificate server...")

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleCertificate)

	certPEM, err := tls.X509KeyPair(cert, pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(certKey),
		},
	))
	if err != nil {
		return err
	}

	srv := http.Server{
		Addr: certificatePort,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certPEM},
		},
		Handler: mux,
	}

	go func() {
		l.Infof("Certificate server is listening on %s\n", certificatePort)
		if err := srv.ListenAndServeTLS("", ""); err != nil {
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

func handleCertificate(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Certificate Server OK"))
}
