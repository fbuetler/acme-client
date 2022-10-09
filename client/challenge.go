package client

import (
	"acme/jws"
	"acme/servers"
	"crypto/rsa"
	"errors"
	"strings"

	log "github.com/sirupsen/logrus"
)

func (c *client) solveChallenge() error {
	var urls []string
	var ps []servers.Provision
	for _, a := range c.auths {
		url, token, err := getChallenge(a.Challenges, c.challengeType)
		if err != nil {
			return err
		}

		thumbprint, err := generateKeyAuthorization(c.signer.Signer, &c.signer.Signer.PublicKey, token)
		if err != nil {
			return err
		}

		ps = append(ps, servers.Provision{Token: token, Thumbprint: thumbprint})
		urls = append(urls, url)
	}

	// TODO run dns challenger server in case of dns-01
	// TODO tear down after challenge verfication
	err := servers.RunChallengeServer(ps)
	if err != nil {
		return err
	}

	for _, url := range urls {
		err = c.respondToAuthorization(url)
		if err != nil {
			return err
		}
	}

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
	log.Debug("Computed key authorization.")

	return keyAuthorization, nil
}
