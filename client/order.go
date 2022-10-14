package client

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// Each account object includes an "orders" URL from which a list of
// orders created by the account can be fetched via POST-as-GET request.
// The result of the request MUST be a JSON object whose "orders" field
// is an array of URLs, each identifying an order belonging to the
// account.
type ordersList struct {
	Orders []string `json:"orders,omitempty"`
}

// An ACME order object represents a client's request for a certificate
// and is used to track the progress of that order through to issuance.
type order struct {
	Status            string       `json:"status,omitempty"`
	Identifiers       []identifier `json:"identifiers,omitempty"`
	AuthorizationURLs []string     `json:"authorizations,omitempty"`
	FinalizeURL       string       `json:"finalize,omitempty"`
	CertificateURL    string       `json:"certificate,omitempty"`
	NotBefore         string       `json:"notBefore,omitempty"`
	NotAfter          string       `json:"notAfter,omitempty"`
	Expires           string       `json:"expires,omitempty"`
}

type identifier struct {
	Status string
	Type   string `json:"type,omitempty"` // usually 'dns'
	Values string `json:"value,omitempty"`
}

type CSR struct {
	CSR string `json:"csr"`
}

func (c *client) submitOrder() error {
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
	resp, err := c.send(url, c.kid, o, http.StatusCreated, &c.order)
	if err != nil {
		log.WithError(err).Error("Failed to submit order.")
		return err
	}

	c.orderURL = resp.Header.Get("Location")

	log.WithFields(log.Fields{"order": fmt.Sprintf("%+v", c.order)}).Info("Order submitted.")
	return nil
}

func (c *client) pollForOrderStatusChange(url string, respOrder *order) error {
	for {
		log.Info("Polling for status...")

		err := c.getOrder(url, respOrder)
		if err != nil {
			return err
		}

		if respOrder.Status == "valid" || respOrder.Status == "invalid" {
			log.Infof("Order status changed: %s", respOrder.Status)

			if respOrder.Status == "invalid" {
				err = errors.New("invalid order")
				log.WithError(err).Error("Order failed.")
				return err
			}
			break
		}

		time.Sleep(1 * time.Second)
	}

	return nil
}

func (c *client) getOrder(url string, respOrder *order) error {
	_, err := c.send(url, c.kid, nil, http.StatusOK, respOrder)
	if err != nil {
		log.WithError(err).Error("Failed to get order.")
		return err
	}

	return nil
}

func (c *client) finalizeOrder() error {
	domain := c.domains[0]
	san := []string{domain}
	for _, d := range c.domains {
		if d != domain {
			san = append(san, d)
		}
	}

	err := c.generateCertificateKeyPair()
	if err != nil {
		return err
	}

	encodedCSR, err := encodeCSR(c.certKey, domain, san)
	if err != nil {
		log.WithError(err).Error("Failed to encode CSR.")
		return err
	}

	url := c.order.FinalizeURL
	csr := CSR{
		CSR: encodedCSR,
	}

	var o order
	_, err = c.send(url, c.kid, csr, http.StatusOK, &o)
	if err != nil {
		log.WithError(err).Error("Failed to finalizeOrder.")
		return err
	}

	log.WithFields(log.Fields{"order": fmt.Sprintf("%+v", o)}).Info("Order finalized.")
	return nil
}
