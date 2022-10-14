package client

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strings"

	log "github.com/sirupsen/logrus"

	"acme/jws"
	"acme/servers"
)

type provision struct {
	domain  string
	keyAuth string
	token   string
	url     string
}

func (c *client) solveChallenge(closeDNSServer chan struct{}, closeChalServer chan struct{}) error {
	var ps []provision
	for _, a := range c.auths {
		url, token, err := getChallenge(a.Challenges, c.challengeType)
		if err != nil {
			return err
		}

		keyAuth, err := generateKeyAuthorization(c.signer.Signer, &c.signer.Signer.PublicKey, token)
		if err != nil {
			return err
		}

		ps = append(ps, provision{
			domain:  a.Identifier.Values,
			keyAuth: keyAuth,
			token:   token,
			url:     url,
		})
	}

	if c.challengeType == HTTPchallenge {
		err := solveHTTPchallenge(closeChalServer, ps)
		if err != nil {
			return err
		}

		err = solveDNSchallenge(closeDNSServer, nil, c.record)
		if err != nil {
			return err
		}
	} else if c.challengeType == DNSchallenge {
		err := solveDNSchallenge(closeDNSServer, ps, c.record)
		if err != nil {
			return err
		}
	} else {
		return errors.New("unknown challenge type")
	}

	for _, p := range ps {
		err := c.respondToAuthorization(p.url)
		if err != nil {
			return err
		}
	}

	err := c.pollForAuthStatusChange()
	if err != nil {
		return err
	}

	return nil
}

func solveHTTPchallenge(closeChalServer chan struct{}, provisions []provision) error {
	var ps []servers.HTTPProvision
	for _, p := range provisions {
		ps = append(ps, servers.HTTPProvision{Token: p.token, Thumbprint: p.keyAuth})
	}

	// TODO tear down after challenge verfication
	err := servers.RunChallengeServer(closeChalServer, ps)
	if err != nil {
		return err
	}

	return nil
}

func solveDNSchallenge(closeDNSServer chan struct{}, provisions []provision, record string) error {
	var ps []servers.DNSProvision
	for _, p := range provisions {
		hasher := crypto.SHA256.New()
		hasher.Write([]byte(p.keyAuth))
		keyAuthDigest := hasher.Sum(nil)

		ps = append(ps, servers.DNSProvision{
			Domain:  p.domain,
			KeyAuth: base64.RawURLEncoding.EncodeToString(keyAuthDigest),
		})
	}

	servers.RunDNSServer(closeDNSServer, ps, record)

	return nil
}

func getChallenge(cs []challenge, challengeType string) (string, string, error) {
	var url string
	var t string
	for _, c := range cs {
		if c.Type == challengeType {
			t = c.Token
			url = c.URL
		}
	}

	if len(t) == 0 {
		return "", "", errors.New("no suited challenge available")
	}

	return url, t, nil
}

func generateKeyAuthorization(signer *rsa.PrivateKey, publicKey *rsa.PublicKey, token string) (string, error) {
	keyThumbprint, err := jws.ComputeKeyThumbprint(signer, publicKey)
	if err != nil {
		log.WithError(err).Error("Failed to compute key thumbprint")
		return "", err
	}

	keyAuthorization := strings.Join([]string{token, keyThumbprint}, ".")
	// log.Debug("Computed key authorization.")

	return keyAuthorization, nil
}
