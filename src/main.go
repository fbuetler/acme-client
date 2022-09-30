package main

import (
	"crypto/x509"
	"errors"
	"io/ioutil"

	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
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

	runDNSServer(opts.Record)
	runChallengeServer()
	runCertificateServer()
	runShutdownServer()
}
