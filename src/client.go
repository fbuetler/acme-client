package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type orderStatus int
type authorizationStatus int
type challengeStatus int
type accountStatus int

const (
	ORDER_PENDING orderStatus = iota
	ORDER_READY
	ORDER_PROCESSING
	ORDER_VALID
	ORDER_INVALID
)

const (
	AUTHORIZATION_PENDING authorizationStatus = iota
	AUTHORIZATION_VALID
	AUTHORIZATION_INVALID
	AUTHORIZATION_DEACTIVATED
	AUTHORIZATION_EXPIRED
	AUTHORIZATION_REVOKED
)

const (
	CHALLENGE_PENDING challengeStatus = iota
	CHALLENGE_PROCESSING
	CHALLENGE_VALID
	CHALLENGE_INVALID
)

const (
	ACCOUNT_VALID accountStatus = iota
	ACCOUNT_DEACTIVATED
	ACCOUNT_REVOKED
)

// In order to help clients configure themselves with the right URLs for
// each ACME operation, ACME servers provide a directory object.
type dir struct {
	KeyChangeURL  string `json:"keyChange"`
	NewAccountURL string `json:"newAccount"`
	NewNonceURL   string `json:"newNonce"`
	NewOrderURL   string `json:"newOrder"`
	RevokeCertURL string `json:"revokeCert"`
}

// An ACME account resource represents a set of metadata associated with an account.
type account struct {
	Status    accountStatus `json:"status"`
	OrdersURL []string      `json:"orders"`
}

// Each account object includes an "orders" URL from which a list of
// orders created by the account can be fetched via POST-as-GET request.
// The result of the request MUST be a JSON object whose "orders" field
// is an array of URLs, each identifying an order belonging to the
// account.
type ordersList struct {
	Orders []string `json:"orders"`
}

// An ACME order object represents a client's request for a certificate
// and is used to track the progress of that order through to issuance.
type order struct {
	Status            orderStatus  `json:"status"`
	Identifiers       []identifier `json:"identifiers"`
	AuthorizationURLs []string     `json:"authorizations"`
	FinalizeURL       string       `json:"finalize"`
	CertificateURL    string       `json:"certificate"`
	// expires
	// notBefore
	// notAfter
}

type identifier struct {
	Type   string `json:"type"` // usually 'dns'
	Values string `json:"value"`
}

// An ACME authorization object represents a server's authorization for
// an account to represent an identifier.
type authorization struct {
	Identifier identifier          `json:"identifier"`
	Status     authorizationStatus `json:"status"`
	Challenges []challenge         `json:"challenges"`
	Wildcard   bool                `json:"wildcard"`
	// expires
}

// An ACME challenge object represents a server's offer to validate a
// client's possession of an identifier in a specific way.
type challenge struct {
	// content depends on challenge TODO -> RFC Section 8
}

type client struct {
	httpClient    http.Client
	directoryURL  string
	dir           dir
	challengeType string
	domains       []string
	nonce         string
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
	err = c.loadDirectory()
	if err != nil {
		return err
	}

	err = c.getNonce()
	if err != nil {
		return err
	}

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

	log.WithField("directory", c.dir).Debug("Received directory.")
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

	return nil
}

func (c *client) RevokeCert() error {
	return nil
}
