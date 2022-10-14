package main

import (
	"crypto/x509"
	"errors"
	"io/ioutil"

	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"

	"acme/client"
	"acme/servers"
)

const (
	thrustrootCert = "project/pebble.minica.pem"
)

var opts struct {
	Positional struct {
		ChallengeType string `positional-arg-name:"Challenge type" choice:"dns01" choice:"http01" required:"yes" description:"Challenge type indicates which ACME challenge type the client should perform"`
	} `positional-args:"yes"`

	Dir string `long:"dir" required:"yes" description:"Directory is the URL of the ACME server that shoule be used"`

	Record string `long:"record" required:"yes" description:"Record is the IPv4 address which must be returned by your DNS server for all A-record queries."`

	Domains []string `long:"domain" required:"yes" description:"Domains is a the domain for which to request the certificate"`

	Revoke bool `long:"revoke" description:"If present, your application should immediately revoke the certificate after obtaining it"`

	// Slice of bool will append 'true' each time the option is encountered (can be set multiple times, like -vvv)
	Verbose []bool `short:"v" long:"verbose" description:"Show verbose debug information"`
}

func init() {
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true
	log.SetFormatter(customFormatter)
	log.SetLevel(log.DebugLevel)
}

func main() {
	_, err := flags.Parse(&opts)
	if err != nil {
		log.Fatal(err)
	}

	closeDNSServer := make(chan struct{}, 1)
	closeCertServer := make(chan struct{}, 1)
	closeChalServer := make(chan struct{}, 1)

	rootCAs, err := loadThrustrootCert()
	if err != nil {
		log.WithError(err).Fatal("Failed to load thrust root cert.")
	}

	c := client.NewClient(rootCAs, opts.Dir, opts.Positional.ChallengeType, opts.Domains, opts.Record)
	err = c.IssueCertificate(closeDNSServer, closeCertServer, closeChalServer)
	if err != nil {
		log.WithError(err).Fatal("Failed to issue certificate.")
	}

	if opts.Revoke {
		err = c.RevokeCert()
		if err != nil {
			log.WithError(err).Fatal("Failed to revoke certificate.")
		}
	}

	servers.RunShutdownServer(closeDNSServer, closeCertServer, closeChalServer)
}

func loadThrustrootCert() (*x509.CertPool, error) {
	log.Debug("Create cert pool")
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	log.Debug("Read thrust root cert")
	certs, err := ioutil.ReadFile(thrustrootCert)
	if err != nil {
		log.WithField("file", thrustrootCert).WithError(err).Errorf("Failed to read file.")
		return nil, err
	}

	log.Debug("Adding thrust root cert to cert pool")
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.WithField("file", thrustrootCert).Error("Failed to add thrust root cert to cert pool.")
		return nil, errors.New("no cert added")
	}

	return rootCAs, nil
}
