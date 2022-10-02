package client

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"

	"acme/src/jws"
)

type orderStatus string
type authorizationStatus string
type challengeStatus string
type accountStatus string

const (
	ORDER_PENDING    orderStatus = "pending"
	ORDER_READY      orderStatus = "ready"
	ORDER_PROCESSING orderStatus = "processing"
	ORDER_VALID      orderStatus = "valid"
	ORDER_INVALID    orderStatus = "invalid"
)

const (
	AUTHORIZATION_PENDING     authorizationStatus = "pending"
	AUTHORIZATION_VALID       authorizationStatus = "valid"
	AUTHORIZATION_INVALID     authorizationStatus = "invalid"
	AUTHORIZATION_DEACTIVATED authorizationStatus = "deactivated"
	AUTHORIZATION_EXPIRED     authorizationStatus = "expired"
	AUTHORIZATION_REVOKED     authorizationStatus = "revoked"
)

const (
	CHALLENGE_PENDING    challengeStatus = "pending"
	CHALLENGE_PROCESSING challengeStatus = "processing"
	CHALLENGE_VALID      challengeStatus = "valid"
	CHALLENGE_INVALID    challengeStatus = "invalid"
)

const (
	ACCOUNT_VALID       accountStatus = "valid"
	ACCOUNT_DEACTIVATED accountStatus = "deactivated"
	ACCOUNT_REVOKED     accountStatus = "revoked"
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

// An ACME account resource represents a set of metadata associated with an account.
type account struct {
	Status               accountStatus `json:"status,omitempty"`
	OrdersURL            string        `json:"orders,omitempty"`
	TermsOfServiceAgreed bool          `json:"termsOfServiceAgreed,omitempty"`
}

// Each account object includes an "orders" URL from which a list of
// orders created by the account can be fetched via POST-as-GET request.
// The result of the request MUST be a JSON object whose "orders" field
// is an array of URLs, each identifying an order belonging to the
// account.
type ordersList struct {
	Orders []string `json:"orders,omitempty"`
}

// An ACME order object represents a client's request for a certificate
// and is used to track the progress of that order through to issuance.
type order struct {
	Status            orderStatus  `json:"status,omitempty"`
	Identifiers       []identifier `json:"identifiers,omitempty"`
	AuthorizationURLs []string     `json:"authorizations,omitempty"`
	FinalizeURL       string       `json:"finalize,omitempty"`
	CertificateURL    string       `json:"certificate,omitempty"`
	// expires
	// notBefore
	// notAfter
}

type identifier struct {
	Type   string `json:"type,omitempty"` // usually 'dns'
	Values string `json:"value,omitempty"`
}

// An ACME authorization object represents a server's authorization for
// an account to represent an identifier.
type authorization struct {
	Identifier identifier          `json:"identifier,omitempty"`
	Status     authorizationStatus `json:"status,omitempty"`
	Challenges []challenge         `json:"challenges,omitempty"`
	Wildcard   bool                `json:"wildcard,omitempty"`
	// expires
}

// An ACME challenge object represents a server's offer to validate a
// client's possession of an identifier in a specific way.
type challenge struct {
	// content depends on challenge TODO -> RFC Section 8
}

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

func (c *client) generateKeypair() error {
	bits := 2048
	l := log.WithField("bits", bits)

	signer, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		l.WithError(err).Error("Failed to generate private key")
		return err
	}

	c.signer = signer

	l.Debug("Generated key pair.")
	return nil
}

func (c *client) loadDirectory() error {
	l := log.WithField("directoryURL", c.directoryURL)

	resp, err := c.httpClient.Get(c.directoryURL)
	if err != nil {
		l.WithError(err).Error("Failed to get directory URL.")
		return err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&c.dir)
	if err != nil {
		l.WithError(err).Error("Failed to decode JSON.")
		return err
	}

	log.WithFields(log.Fields{"directory": fmt.Sprintf("%+v", c.dir)}).Debug("Received directory.")
	return nil
}

func (c *client) getNonce() error {
	resp, err := c.httpClient.Head(c.dir.NewNonceURL)
	if err != nil {
		log.WithError(err).Error("Failed to get nonce.")
		return err
	}
	defer resp.Body.Close()

	nonce := resp.Header.Get("Replay-Nonce")
	if len(nonce) == 0 {
		err = errors.New("nonce not found")
		log.WithError(err).Error("Failed to extract nonce from header.")
		return err
	}

	c.nonce = nonce
	log.WithField("nonce", nonce).Debug("Received nonce.")
	return nil
}

func (c *client) createAccount() error {
	payload := account{
		TermsOfServiceAgreed: true,
	}
	targetURL := c.dir.NewAccountURL

	accountJWS, err := jws.GenerateJWS(c.signer, c.nonce, targetURL, payload)
	if err != nil {
		log.WithError(err).Error("Failed to generate JWS.")
		return err
	}

	resp, err := c.httpClient.Post(targetURL, "application/jose+json", bytes.NewBuffer(accountJWS))
	if err != nil {
		log.WithError(err).Error("Failed to create account.")
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.WithError(err).Error("Failed to read response body.")
			return err
		}
		body := string(bodyBytes)

		err = errors.New("unexpected status code")
		log.WithField("status code", resp.StatusCode).WithField("body", body).WithError(err).Error("Account creation failed.")
		return err
	}

	err = json.NewDecoder(resp.Body).Decode(&c.account)
	if err != nil {
		log.WithError(err).Error("Failed to decode JSON.")
		return err
	}

	log.WithFields(log.Fields{"account": fmt.Sprintf("%+v", c.account)}).Debug("Account created.")
	return nil
}

func (c *client) submitOrder() error {
	return nil
}

func (c *client) fetchChallenges() error {
	return nil
}

func (c *client) repondToChallenges() error {
	return nil
}

func (c *client) pollForStatus() error {
	return nil
}

func (c *client) finalizeOrder() error {
	return nil
}

func (c *client) downloadCert() error {
	return nil
}

func (c *client) RevokeCert() error {
	return nil
}
