package client

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"acme/jws"
	"acme/servers"
)

type empty struct{}

type client struct {
	httpClient    http.Client     // http client used for all requests to the ACME server
	directoryURL  string          // directory URL to bootstrap the client configuration
	challengeType string          // challenge type that should be used
	domains       []string        // domains to issue a certificate for
	signer        *jws.Signer     // signing key
	dir           dir             // directory with the client configuration
	account       account         // account connected with the key pair above
	kid           string          // URL to the account
	order         order           // placed order
	orderURL      string          // URL to the placed order
	auths         []authorization // any of these challenge has to be completed
	certKey       *rsa.PrivateKey // private key for the signed certificate
	cert          []byte          // signed certificate
}

func NewClient(rootCAs *x509.CertPool, directoryURL, challengeType string, domains []string) *client {
	config := &tls.Config{
		RootCAs: rootCAs,
	}
	tr := &http.Transport{TLSClientConfig: config}
	httpClient := &http.Client{Transport: tr}

	var ct string
	switch challengeType {
	case "http01":
		ct = "http-01"
	case "dns01":
		ct = "dns-01"
	default:
		ct = "http-01" // or should it fail?
	}

	return &client{
		httpClient:    *httpClient,
		directoryURL:  directoryURL,
		challengeType: ct,
		domains:       domains,
	}
}

func (c *client) IssueCertificate() error {
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

	err = c.submitOrder()
	if err != nil {
		return err
	}

	err = c.fetchAuthorizations()
	if err != nil {
		return err
	}

	chalURL, token, err := c.getChallenge()
	if err != nil {
		return err
	}

	keyAuthorization, err := c.generateKeyAuthorization(token)
	if err != nil {
		return err
	}

	// TODO run dns challenger server in case of dns-01
	// TODO tear down after challenge verfication
	err = servers.RunChallengeServer(token, keyAuthorization)
	if err != nil {
		return err
	}

	// TODO wait for challenge server to be up
	time.Sleep(1 * time.Second)

	err = c.respondToAuthorization(chalURL)
	if err != nil {
		return err
	}

	// TODO give some time to verify the challenge
	time.Sleep(5 * time.Second)

	err = c.pollForAuthStatusChange()
	if err != nil {
		return err
	}

	err = c.finalizeOrder()
	if err != nil {
		return err
	}

	var order order
	err = c.pollForOrderStatusChange(c.orderURL, &order)
	if err != nil {
		return err
	}

	err = c.downloadCert(order)
	if err != nil {
		return err
	}

	err = servers.RunCertificateServer(c.cert, c.certKey)
	if err != nil {
		return err
	}

	// TODO wait for certificate server to be up
	time.Sleep(1 * time.Second)

	return nil
}

func (c *client) send(url, kid string, reqPayload interface{}, expectedStatusCode int, respPayload interface{}) (*http.Response, error) {
	nonce, err := c.getNonce()
	if err != nil {
		return nil, err
	}

	jws, err := c.signer.Encode(nonce, url, kid, reqPayload)
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
		log.Debug("Request succeeded. Returing without decoding.")
		return resp, nil
	}

	err = json.NewDecoder(resp.Body).Decode(respPayload)
	if err != nil {
		log.WithError(err).Error("Failed to decode JSON.")
		return nil, err
	}
	log.WithField("payload", fmt.Sprintf("%+v", respPayload)).Debug("Received response.")

	log.Debug("Request succeeded.")
	return resp, nil
}

func (c *client) generateKeyAuthorization(token string) (string, error) {

	// token
	// account key
	keyThumbprint, err := jws.ComputeKeyThumbprint(c.signer.Signer)
	if err != nil {
		log.WithError(err).Error("Failed to compute key thumbprint")
		return "", err
	}

	keyAuthorization := strings.Join([]string{token, keyThumbprint}, ".")
	log.Debug("Computed key authorization.")

	return keyAuthorization, nil
}

func (c *client) getChallenge() (string, string, error) {
	var url string
	var t string
	for _, a := range c.auths {
		for _, chal := range a.Challenges {
			if chal.Type == c.challengeType {
				t = chal.Token
				url = chal.URL
			}
		}
	}

	if len(t) == 0 {
		return "", "", errors.New("no suited challenge available")
	}

	return url, t, nil
}