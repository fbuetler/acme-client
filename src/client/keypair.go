package client

import (
	"crypto/rand"
	"crypto/rsa"

	log "github.com/sirupsen/logrus"
)

const (
	KeyBits = 2048
)

func (c *client) generateKeypair() error {
	signer, err := rsa.GenerateKey(rand.Reader, KeyBits)
	if err != nil {
		log.WithError(err).Error("Failed to generate private key")
		return err
	}

	c.signer = signer

	log.Debug("Generated key pair.")
	return nil
}
