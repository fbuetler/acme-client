package client

import (
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"

	"acme/src/jws"
)

type accountStatus string

const (
	ACCOUNT_VALID       accountStatus = "valid"
	ACCOUNT_DEACTIVATED accountStatus = "deactivated"
	ACCOUNT_REVOKED     accountStatus = "revoked"
)

// An ACME account resource represents a set of metadata associated with an account.
type account struct {
	Status               accountStatus `json:"status,omitempty"`
	OrdersURL            string        `json:"orders,omitempty"`
	TermsOfServiceAgreed bool          `json:"termsOfServiceAgreed,omitempty"`
}

func (c *client) createAccount() error {
	a := account{
		TermsOfServiceAgreed: true,
	}
	url := c.dir.NewAccountURL

	headers, err := c.send(url, jws.NoKeyID, a, http.StatusCreated, &c.account)
	if err != nil {
		log.WithError(err).Error("Failed to create Account.")
		return err
	}

	c.kid = headers.Get("Location")

	log.WithFields(log.Fields{"account": fmt.Sprintf("%+v", c.account)}).Debug("Account created.")
	return nil
}
