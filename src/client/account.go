package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	payload := account{
		TermsOfServiceAgreed: true,
	}
	targetURL := c.dir.NewAccountURL

	j, err := jws.New(c.signer)
	if err != nil {
		log.WithError(err).Error("Failed to setup JWS.")
		return err
	}

	accountJWS, err := j.Encode(c.nonce, targetURL, jws.NoKeyID, payload)
	if err != nil {
		log.WithError(err).Error("Failed to generate JWS.")
		return err
	}

	resp, err := c.httpClient.Post(targetURL, "application/jose+json", bytes.NewBuffer(accountJWS))
	if err != nil {
		log.WithError(err).Error("Failed to create account.")
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.WithError(err).Error("Failed to read response body.")
			return err
		}
		body := string(bodyBytes)

		err = errors.New("unexpected status code")
		log.WithField("status code", resp.StatusCode).WithField("body", body).WithError(err).Error("Account creation failed.")
		return err
	}

	err = json.NewDecoder(resp.Body).Decode(&c.account)
	if err != nil {
		log.WithError(err).Error("Failed to decode JSON.")
		return err
	}

	log.WithFields(log.Fields{"account": fmt.Sprintf("%+v", c.account)}).Debug("Account created.")
	return nil
}
