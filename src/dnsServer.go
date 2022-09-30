package main

import (
	"net"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const (
	DNSPort = ":10053"
)

func runDNSServer(record string) error {
	log.Info("Starting DNS server...")

	dnsMux := dns.NewServeMux()
	dnsMux.HandleFunc(".", handleDNSrequest(record))

	srv := &dns.Server{Addr: DNSPort, Net: "udp", Handler: dnsMux}

	go func() {
		log.Infof("DNS server is listening on %s\n", DNSPort)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set udp listener %s\n", err.Error())
		}
	}()

	return nil
}

func handleDNSrequest(record string) dns.HandlerFunc {
	// all queries will be answered with the provided record
	return func(w dns.ResponseWriter, r *dns.Msg) {
		msg := dns.Msg{}
		msg.SetReply(r)

		domain := msg.Question[0].Name
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   net.ParseIP(record),
		})
		w.WriteMsg(&msg)
	}
}
