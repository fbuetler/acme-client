package client

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
)

// In order to help clients configure themselves with the right URLs for
// each ACME operation, ACME servers provide a directory object.
type dir struct {
	KeyChangeURL  string `json:"keyChange,omitempty"`
	NewAccountURL string `json:"newAccount,omitempty"`
	NewNonceURL   string `json:"newNonce,omitempty"`
	NewOrderURL   string `json:"newOrder,omitempty"`
	RevokeCertURL string `json:"revokeCert,omitempty"`
}

func (c *client) loadDirectory() error {
	resp, err := c.httpClient.Get(c.directoryURL)
	if err != nil {
		log.WithError(err).Error("Failed to get directory URL.")
		return err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&c.dir)
	if err != nil {
		log.WithError(err).Error("Failed to decode JSON.")
		return err
	}

	log.WithFields(log.Fields{"directory": fmt.Sprintf("%+v", c.dir)}).Info("Received directory.")
	return nil
}
