package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"

	log "github.com/sirupsen/logrus"
)

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
	return nil
}

func (c *client) RevokeCert() error {
	return nil
}
