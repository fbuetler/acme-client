package servers

import (
	"net"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const (
	dnsPort = ":10053"
)

func RunDNSServer(close chan struct{}, record string) error {
	l := log.WithField("component", "DNS server")

	l.Info("Starting DNS server...")

	dnsMux := dns.NewServeMux()
	dnsMux.HandleFunc(".", handleDNSrequest(l, record))

	srv := &dns.Server{Addr: dnsPort, Net: "udp", Handler: dnsMux}

	go func() {
		l.Infof("DNS server is listening on %s\n", dnsPort)
		if err := srv.ListenAndServe(); err != nil {
			l.Errorf("Failed to set udp listener %s\n", err.Error())
		}
	}()

	go func() {
		<-close
		l.Info("Received shutdown signal. Terminating...")
		srv.Shutdown()
	}()

	return nil
}

func handleDNSrequest(l *log.Entry, record string) dns.HandlerFunc {
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

		l.Infof("Responded to %s with %s", domain, record)
	}
}
