package client

import (
	"errors"

	log "github.com/sirupsen/logrus"
)

func (c *client) getNonce() (string, error) {
	resp, err := c.httpClient.Head(c.dir.NewNonceURL)
	if err != nil {
		log.WithError(err).Error("Failed to get nonce.")
		return "", err
	}
	defer resp.Body.Close()

	nonce := resp.Header.Get("Replay-Nonce")
	if len(nonce) == 0 {
		err = errors.New("nonce not found")
		log.WithError(err).Error("Failed to extract nonce from header.")
		return "", err
	}

	log.WithField("nonce", nonce).Debug("Received nonce.")
	return nonce, nil
}
