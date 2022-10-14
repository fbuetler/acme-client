package client

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// An ACME authorization object represents a server's authorization for
// an account to represent an identifier.
type authorization struct {
	Identifier identifier  `json:"identifier,omitempty"`
	Status     string      `json:"status,omitempty"`
	Challenges []challenge `json:"challenges,omitempty"`
	Wildcard   bool        `json:"wildcard,omitempty"`
	// expires
}

// An ACME challenge object represents a server's offer to validate a
// client's possession of an identifier in a specific way.
type challenge struct {
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

		c.auths = append(c.auths, auth)
	}

	log.WithFields(log.Fields{"authorizations": fmt.Sprintf("%+v", c.auths)}).Info("Authorizations fetched.")
	return nil
}

func (c *client) respondToAuthorization(url string) error {
	_, err := c.send(url, c.kid, empty{}, http.StatusOK, &empty{})
	if err != nil {
		log.WithError(err).Error("Failed to send challenge acknowledgement.")
		return err
	}

	log.Info("Sent challenge acknowledgement.")
	return nil
}

func (c *client) pollForAuthStatusChange() error {
	for _, url := range c.order.AuthorizationURLs {
		for {
			log.Info("Polling for status...")

			var auth authorization
			_, err := c.send(url, c.kid, nil, http.StatusOK, &auth)
			if err != nil {
				log.WithError(err).Error("Failed to fetch authorization.")
				return err
			}

			if auth.Status == "valid" || auth.Status == "invalid" {
				log.Infof("Authorization status changed: %s", auth.Status)

				if auth.Status == "invalid" {
					err = errors.New("invalid authorization")
					log.WithError(err).Error("Authorization failed.")
					return err
				}
				break
			}

			time.Sleep(1 * time.Second)
		}
	}

	return nil
}
