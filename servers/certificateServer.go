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
	CertificatePort = ":5001"
)

func RunCertificateServer(cert []byte, certKey *rsa.PrivateKey) error {
	log.Info("Starting Certificate server...")

	certificateMux := http.NewServeMux()
	certificateMux.HandleFunc("/", handleCertificate)

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
		Addr: CertificatePort,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certPEM},
		},
		Handler: certificateMux,
	}

	go func() {
		log.Infof("Certificate server is listening on %s\n", CertificatePort)
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("Failed to serve %s\n", err.Error())
		}
	}()

	return nil
}

func handleCertificate(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Certificate Server OK"))
}
