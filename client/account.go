package client

import (
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"

	"acme/jws"
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

	resp, err := c.send(url, jws.NoKeyID, a, http.StatusCreated, &c.account)
	if err != nil {
		log.WithError(err).Error("Failed to create Account.")
		return err
	}

	c.kid = resp.Header.Get("Location")

	log.WithFields(log.Fields{"account": fmt.Sprintf("%+v", c.account)}).Info("Account created.")
	return nil
}
