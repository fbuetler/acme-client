package client

import (
	"crypto/rand"
	"crypto/rsa"

	log "github.com/sirupsen/logrus"

	"acme/src/jws"
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

	c.signer, err = jws.New(signer)
	if err != nil {
		log.WithError(err).Error("Failed to setup Signer.")
		return err
	}

	log.Debug("Generated key pair.")
	return nil
}
