package client

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"
)

// PKCS #10: Certification Request Syntax Specification
// See https://www.rfc-editor.org/rfc/rfc2986
func encodeCSR(signer crypto.Signer, domain string, sans []string) (string, error) {
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

func (c *client) downloadCert(o order) error {
	url := o.CertificateURL
	resp, err := c.send(url, c.kid, nil, http.StatusOK, nil)
	if err != nil {
		log.WithError(err).Error("Failed to download certificate.")
		return err
	}

	c.cert, err = io.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("Failed to read response body.")
		return err
	}

	return nil
}

// In order to provide easy interoperation with TLS, the first
// certificate MUST be an end-entity certificate.  Each following
// certificate SHOULD directly certify the one preceding it.
// See https://www.rfc-editor.org/rfc/rfc8555#section-9.1
func parseDownloadedCert(cert []byte) ([]byte, []byte) {
	_, issuer := pem.Decode(cert)
	return bytes.TrimSuffix(cert, issuer), issuer
}

func (c *client) RevokeCert() error {
	return nil
}
