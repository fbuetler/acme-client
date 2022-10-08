package client

import (
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

type authorizationStatus string
type challengeStatus string

const (
	AUTHORIZATION_PENDING     authorizationStatus = "pending"
	AUTHORIZATION_VALID       authorizationStatus = "valid"
	AUTHORIZATION_INVALID     authorizationStatus = "invalid"
	AUTHORIZATION_DEACTIVATED authorizationStatus = "deactivated"
	AUTHORIZATION_EXPIRED     authorizationStatus = "expired"
	AUTHORIZATION_REVOKED     authorizationStatus = "revoked"
)

const (
	CHALLENGE_PENDING    challengeStatus = "pending"
	CHALLENGE_PROCESSING challengeStatus = "processing"
	CHALLENGE_VALID      challengeStatus = "valid"
	CHALLENGE_INVALID    challengeStatus = "invalid"
)

// An ACME authorization object represents a server's authorization for
// an account to represent an identifier.
type authorization struct {
	Identifier identifier          `json:"identifier,omitempty"`
	Status     authorizationStatus `json:"status,omitempty"`
	Challenges []challenge         `json:"challenges,omitempty"`
	Wildcard   bool                `json:"wildcard,omitempty"`
	// expires
}

// An ACME challenge object represents a server's offer to validate a
// client's possession of an identifier in a specific way.
type challenge struct {
	// content depends on challenge TODO -> RFC Section 8
	Type      string `json:"type"`
	URL       string `json:"url"`
	Status    string `json:"status"`
	Validated string `json:"validated"`
	Token     string `json:"token"`
}

func (c *client) fetchAuthorizations() error {
	for _, url := range c.order.AuthorizationURLs {
		var auth authorization
		_, err := c.send(url, c.kid, nil, http.StatusOK, &auth)
		if err != nil {
			log.WithError(err).Error("Failed to fetch authorizations.")
			return err
		}

		// TODO maybe only save auths where the challenge type matches
		c.auths = append(c.auths, auth)
	}

	log.WithFields(log.Fields{"authorizations": fmt.Sprintf("%+v", c.auths)}).Debug("Authorizations fetched.")
	return nil
}

func (c *client) respondToAuthorization(url string) error {
	_, err := c.send(url, c.kid, empty{}, http.StatusOK, &empty{})
	if err != nil {
		log.WithError(err).Error("Failed to send challenge acknowledgement.")
		return err
	}

	log.Debug("Sent challenge acknowledgement.")
	return nil
}

func (c *client) pollForAuthStatusChange() error {
	url := c.order.AuthorizationURLs[0] // TODO hacky

	for {
		log.Debug("Polling for status...")

		var auth authorization
		_, err := c.send(url, c.kid, nil, http.StatusOK, &auth)
		if err != nil {
			log.WithError(err).Error("Failed to fetch authorization.")
			return err
		}

		if auth.Status == "valid" || auth.Status == "invalid" {
			log.Debugf("Authorization status changed: %s", auth.Status)
			break
		}

		time.Sleep(1 * time.Second)
	}

	return nil
}