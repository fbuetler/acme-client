package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"

	"acme/src/jws"
)

type client struct {
	httpClient    http.Client // http client used for all requests to the ACME server
	directoryURL  string      // directory URL to bootstrap the client configuration
	challengeType string      // challenge type that should be used
	domains       []string    // domains to issue a certificate for
	signer        *jws.Signer // signing key
	dir           dir         // directory with the client configuration
	account       account     // account connected with the key pair above
	kid           string      // URL to the account
	order         order       // placed order
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

func (c *client) send(url, kid string, sendPayload interface{}, expectedStatusCode int, recvPayload interface{}) (http.Header, error) {
	nonce, err := c.getNonce()
	if err != nil {
		return nil, err
	}

	jws, err := c.signer.Encode(nonce, url, kid, sendPayload)
	if err != nil {
		log.WithError(err).Error("Failed to encode JWS.")
		return nil, err
	}

	log.Debug("Sending request...")
	resp, err := c.httpClient.Post(url, "application/jose+json", bytes.NewBuffer(jws))
	if err != nil {
		log.WithError(err).Error("Failed to send Request.")
		return nil, err
	}
	defer resp.Body.Close()

	log.Debug("Received response.")
	if resp.StatusCode != expectedStatusCode {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.WithError(err).Error("Failed to read response body.")
			return nil, err
		}
		body := string(bodyBytes)

		err = errors.New("unexpected status code")
		log.WithField("status code", resp.StatusCode).WithField("body", body).WithError(err).Error("Request failed.")
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(recvPayload)
	if err != nil {
		log.WithError(err).Error("Failed to decode JSON.")
		return nil, err
	}

	log.Debug("Request succeeded.")
	return resp.Header, nil
}
