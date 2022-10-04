package client

import (
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type orderStatus string

const (
	ORDER_PENDING    orderStatus = "pending"
	ORDER_READY      orderStatus = "ready"
	ORDER_PROCESSING orderStatus = "processing"
	ORDER_VALID      orderStatus = "valid"
	ORDER_INVALID    orderStatus = "invalid"
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
	Status            orderStatus  `json:"status,omitempty"`
	Identifiers       []identifier `json:"identifiers,omitempty"`
	AuthorizationURLs []string     `json:"authorizations,omitempty"`
	FinalizeURL       string       `json:"finalize,omitempty"`
	CertificateURL    string       `json:"certificate,omitempty"`
	NotBefore         string       `json:"notBefore,omitempty"`
	NotAfter          string       `json:"notAfter,omitempty"`
	Expires           string       `json:"expires,omitempty"`
}

type identifier struct {
	Type   string `json:"type,omitempty"` // usually 'dns'
	Values string `json:"value,omitempty"`
}

func (c *client) submitOrder() error {
	var o order
	for _, d := range c.domains {
		o = order{
			Identifiers: []identifier{
				{
					Type:   "dns",
					Values: d,
				},
			},
		}
	}
	url := c.dir.NewOrderURL

	_, err := c.send(url, c.kid, o, http.StatusCreated, &c.order)
	if err != nil {
		log.WithError(err).Error("Failed to submit Order.")
		return err
	}

	log.WithFields(log.Fields{"order": fmt.Sprintf("%+v", c.order)}).Debug("Order submitted.")
	return nil
}

func (c *client) finalizeOrder() error {
	return nil
}
