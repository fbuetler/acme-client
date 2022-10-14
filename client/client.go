package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"

	"acme/jws"
	"acme/servers"
)

const (
	HTTPchallenge = "http-01"
	DNSchallenge  = "dns-01"
)

type empty struct{}

type client struct {
	record        string   // IP record to be returned by the DNS server for any request
	challengeType string   // challenge type that should be used
	domains       []string // domains to issue a certificate for

	httpClient   http.Client // http client used for all requests to the ACME server
	directoryURL string      // directory URL to bootstrap the client configuration
	dir          dir         // directory with the client configuration

	signer *jws.Signer // signing key of the account
	kid    string      // key ID to the account

	order order // placed order

	cert certPair // signed certificate
}

func NewClient(rootCAs *x509.CertPool, directoryURL, challengeType string, domains []string, record string) *client {
	config := &tls.Config{
		RootCAs: rootCAs,
	}
	tr := &http.Transport{TLSClientConfig: config}
	httpClient := &http.Client{Transport: tr}

	var ct string
	switch challengeType {
	case "http01":
		ct = HTTPchallenge
	case "dns01":
		ct = DNSchallenge
	default:
		ct = HTTPchallenge // or should it fail?
		log.WithField("challenge type", challengeType).Error("invalid challenge type specified")
	}

	return &client{
		httpClient:    *httpClient,
		record:        record,
		challengeType: ct,
		domains:       domains,
		directoryURL:  directoryURL,
	}
}

func (c *client) IssueCertificate(closeDNSServer, closeCertServer, closeChalServer chan struct{}) error {
	err := c.generateAccountKeypair()
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

	auths, err := c.submitOrder()
	if err != nil {
		return err
	}

	err = c.solveChallenge(auths, closeDNSServer, closeChalServer)
	if err != nil {
		return err
	}

	err = c.finalizeOrder()
	if err != nil {
		return err
	}

	err = servers.RunCertificateServer(closeCertServer, c.cert.cert, c.cert.key)
	if err != nil {
		return err
	}

	return nil
}

func (c *client) RevokeCert() error {
	cert, err := parseCert(c.cert.cert)
	if err != nil {
		log.WithError(err).Error("Failed to convert certificate to DER format.")
		return err
	}

	url := c.dir.RevokeCertURL
	r := recvocation{
		Certificate: base64.RawURLEncoding.EncodeToString(cert.Raw),
	}

	_, err = c.send(url, r, http.StatusOK, nil)
	if err != nil {
		log.WithError(err).Error("Failed to revoke certificate.")
		return err
	}

	log.Info("Revoked certificate.")
	return nil
}

func (c *client) send(url string, reqPayload interface{}, expectedStatusCode int, respPayload interface{}) (*http.Response, error) {
	nonce, err := c.getNonce()
	if err != nil {
		return nil, err
	}

	jws, err := c.signer.Encode(nonce, url, c.kid, reqPayload)
	if err != nil {
		log.WithError(err).Error("Failed to encode JWS.")
		return nil, err
	}

	log.WithField("payload", fmt.Sprintf("%+v", reqPayload)).Debugf("Sending request to %s...", url)
	resp, err := c.httpClient.Post(url, "application/jose+json", bytes.NewBuffer(jws))
	if err != nil {
		log.WithError(err).Error("Failed to send Request.")
		return nil, err
	}

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

	if respPayload == nil {
		// log.Debug("Request succeeded. Returning without decoding.")
		return resp, nil
	}

	err = json.NewDecoder(resp.Body).Decode(respPayload)
	if err != nil {
		log.WithError(err).Error("Failed to decode JSON.")
		return nil, err
	}
	log.WithField("payload", fmt.Sprintf("%+v", respPayload)).Debug("Received response.")

	// log.Debug("Request succeeded.")
	return resp, nil
}
