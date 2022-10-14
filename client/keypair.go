package client

import (
	"crypto/rand"
	"crypto/rsa"

	log "github.com/sirupsen/logrus"

	"acme/jws"
)

const (
	KeyBits = 2048
)

func (c *client) generateAccountKeypair() error {
	signer, err := generateKeyPair()
	if err != nil {
		log.WithError(err).Error("Failed to generate private key")
		return err
	}

	c.signer, err = jws.New(signer)
	if err != nil {
		log.WithError(err).Error("Failed to setup Signer.")
		return err
	}

	log.Debug("Generated account key pair.")
	return nil
}

func (c *client) generateCertificateKeyPair() (*rsa.PrivateKey, error) {
	privateKey, err := generateKeyPair()
	if err != nil {
		log.WithError(err).Error("Failed to generate private key")
		return nil, err
	}

	log.Debug("Generated cert key pair.")
	return privateKey, nil
}

func generateKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, KeyBits)
}
