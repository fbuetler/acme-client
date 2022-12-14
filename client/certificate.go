package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type certPair struct {
	cert []byte
	key  *rsa.PrivateKey
}

type recvocation struct {
	Certificate string `json:"certificate,omitempty"`
}

// PKCS #10: Certification Request Syntax Specification
// See https://www.rfc-editor.org/rfc/rfc2986
func encodeCSR(signer *rsa.PrivateKey, domain string, sans []string) (string, error) {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames: sans,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, signer)
	if err != nil {
		log.Error("Failed to create CSR.")
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(csr), nil
}

func (c *client) downloadCert(certificateURL string) ([]byte, error) {
	resp, err := c.send(certificateURL, nil, http.StatusOK, nil)
	if err != nil {
		log.WithError(err).Error("Failed to download certificate.")
		return nil, err
	}

	cert, err := io.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("Failed to read response body.")
		return nil, err
	}

	log.Info("Downloaded issued certificate.")
	return cert, nil
}

func parseCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("failed to decode certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
