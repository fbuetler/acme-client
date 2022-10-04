package client

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net/http"
)

type client struct {
	httpClient    http.Client   // http client used for all requests to the ACME server
	directoryURL  string        // directory URL to bootstrap the client configuration
	challengeType string        // challenge type that should be used
	domains       []string      // domains to issue a certificate for
	signer        crypto.Signer // signing key
	nonce         string        // replay nonce
	dir           dir           // directory with the client configuration
	account       account       // account connected with the key pair above
}

func NewClient(rootCAs *x509.CertPool, directoryURL, challengeType string, domains []string) *client {
	config := &tls.Config{
		RootCAs: rootCAs,
	}
	tr := &http.Transport{TLSClientConfig: config}
	httpClient := &http.Client{Transport: tr}
	return &client{
		httpClient:    *httpClient,
		directoryURL:  directoryURL,
		challengeType: challengeType,
		domains:       domains,
	}
}

func (c *client) IssueCertificate() error {
	err := c.generateKeypair()
	if err != nil {
		return err
	}

	err = c.loadDirectory()
	if err != nil {
		return err
	}

	err = c.getNonce()
	if err != nil {
		return err
	}

	err = c.createAccount()
	if err != nil {
		return err
	}

	err = c.submitOrder()
	if err != nil {
		return err
	}

	err = c.fetchChallenges()
	if err != nil {
		return err
	}

	err = c.repondToChallenges()
	if err != nil {
		return err
	}

	err = c.pollForStatus()
	if err != nil {
		return err
	}

	err = c.finalizeOrder()
	if err != nil {
		return err
	}

	err = c.pollForStatus()
	if err != nil {
		return err
	}

	err = c.downloadCert()
	if err != nil {
		return err
	}

	return nil
}
