package client

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// An ACME order object represents a client's request for a certificate
// and is used to track the progress of that order through to issuance.
type order struct {
	URL               string       `json:"omitempty"`
	Status            string       `json:"status,omitempty"`
	Identifiers       []identifier `json:"identifiers,omitempty"`
	AuthorizationURLs []string     `json:"authorizations,omitempty"`
	FinalizeURL       string       `json:"finalize,omitempty"`
	CertificateURL    string       `json:"certificate,omitempty"`
	NotBefore         string       `json:"notBefore,omitempty"`
	NotAfter          string       `json:"notAfter,omitempty"`
	Expires           string       `json:"expires,omitempty"`
	Error             struct {
		Type string `json:"type,omitempty"`
		Title string `json:"title,omitempty"`
		Status int `json:"status,omitempty"`
		Detail string `json:"detail,omitempty"`
		Instance string `json:"instance,omitempty"`
	}       `json:"error,omitempty"`
}

type identifier struct {
	Status string
	Type   string `json:"type,omitempty"` // usually 'dns'
	Values string `json:"value,omitempty"`
}

type CSR struct {
	CSR string `json:"csr"`
}

func (c *client) submitOrder() ([]authorization, error) {
	var identifiers []identifier
	for _, d := range c.domains {
		identifiers = append(identifiers, identifier{
			Type:   "dns",
			Values: d,
		})
	}
	o := order{
		Identifiers: identifiers,
	}

	url := c.dir.NewOrderURL
	resp, err := c.send(url, o, http.StatusCreated, &c.order)
	if err != nil {
		log.WithError(err).Error("Failed to submit order.")
		return nil, err
	}

	c.order.URL = resp.Header.Get("Location")
	log.WithFields(log.Fields{"order": fmt.Sprintf("%+v", c.order)}).Info("Order submitted.")

	auths, err := c.fetchAuthorizations()
	if err != nil {
		return nil, err
	}

	return auths, nil
}

func (c *client) finalizeOrder() error {
	domain := c.domains[0] // TODO is this correct
	san := []string{domain}
	for _, d := range c.domains {
		if d != domain {
			san = append(san, d)
		}
	}

	certKey, err := c.generateCertificateKeyPair()
	if err != nil {
		return err
	}

	encodedCSR, err := encodeCSR(certKey, domain, san)
	if err != nil {
		log.WithError(err).Error("Failed to encode CSR.")
		return err
	}

	url := c.order.FinalizeURL
	csr := CSR{
		CSR: encodedCSR,
	}

	var o order
	_, err = c.send(url, csr, http.StatusOK, &o)
	if err != nil {
		log.WithError(err).Error("Failed to finalizeOrder.")
		return err
	}

	certificateURL, err := c.pollForOrderStatusChange(c.order.URL)
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{"order": fmt.Sprintf("%+v", o)}).Info("Order finalized.")

	cert, err := c.downloadCert(certificateURL)
	if err != nil {
		return err
	}

	c.cert = certPair{
		cert: cert,
		key:  certKey,
	}

	return nil
}

func (c *client) pollForOrderStatusChange(url string) (string, error) {
	var o order
	for {
		log.Info("Polling for status...")

		err := c.getOrder(url, &o)
		if err != nil {
			return "", err
		}

		if o.Status == "valid" || o.Status == "invalid" {
			log.Infof("Order status changed: %s", o.Status)

			if o.Status == "invalid" {
				err = errors.New("invalid order")
				log.WithError(err).Error("Order failed.")
				return "", err
			}
			break
		}

		time.Sleep(1 * time.Second)
	}

	return o.CertificateURL, nil
}

func (c *client) getOrder(url string, respOrder *order) error {
	_, err := c.send(url, nil, http.StatusOK, respOrder)
	if err != nil {
		log.WithError(err).Error("Failed to get order.")
		return err
	}

	return nil
}
