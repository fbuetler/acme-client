package servers

import (
	"net"
	"strings"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const (
	dnsPort               = ":10053"
	challengeDomainPrefix = "_acme-challenge."
)

type DNSProvision struct {
	Domain  string
	KeyAuth string
}

func RunDNSServer(close chan struct{}, ps []DNSProvision, record string) error {
	l := log.WithField("component", "DNS server")

	l.Info("Starting DNS server...")

	keyAuths := map[string][]string{}
	for _, p := range ps {
		d := challengeDomainPrefix + p.Domain
		if !strings.HasSuffix(p.Domain, ".") {
			d += "."
		}
		keyAuths[d] = append(keyAuths[d], p.KeyAuth) // append only otherwise a lock is required
		l.WithField("Domain", p.Domain).Info("Published validation.")
	}

	dnsMux := dns.NewServeMux()
	dnsMux.HandleFunc(".", handleDNSrequest(l, record, keyAuths))

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

func handleDNSrequest(l *log.Entry, record string, keyAuths map[string][]string) dns.HandlerFunc {
	// all queries will be answered with the provided record
	return func(w dns.ResponseWriter, r *dns.Msg) {
		msg := dns.Msg{}
		msg.SetReply(r)

		domain := msg.Question[0].Name
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   net.ParseIP(record),
		})
		l.Infof("Responded to %s with %s", domain, record)

		if kas, ok := keyAuths[domain]; strings.HasPrefix(domain, challengeDomainPrefix) && ok {
			for _, ka := range kas {
				msg.Answer = append(msg.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
					Txt: []string{ka},
				})
				l.Info("Responded with key authorization")
			}
		}

		w.WriteMsg(&msg)
	}
}
