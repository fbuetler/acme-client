package client

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

// An ACME account resource represents a set of metadata associated with an account.
type account struct {
	Status               string `json:"status,omitempty"`
	OrdersURL            string `json:"orders,omitempty"`
	TermsOfServiceAgreed bool   `json:"termsOfServiceAgreed,omitempty"`
}

func (c *client) createAccount() error {
	a := account{
		TermsOfServiceAgreed: true,
	}
	url := c.dir.NewAccountURL

	resp, err := c.send(url, a, http.StatusCreated, nil)
	if err != nil {
		log.WithError(err).Error("Failed to create Account.")
		return err
	}

	c.kid = resp.Header.Get("Location")

	log.Info("Account created.")
	return nil
}
