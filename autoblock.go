package main

import (
	"errors"
	"expvar"
	"fmt"
	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket/layers"
	"github.com/op/go-logging"
	"github.com/patrickmn/go-cache"
	"net"
	"net/http"
	"os"
	"time"
)

var log = logging.MustGetLogger("autoblock")

var blockReason = map[string]string{
	"127.0.0.2":  "amavis[blocklist.de] or bogon",
	"127.0.0.3":  "apacheddos",
	"127.0.0.4":  "asterisk",
	"127.0.0.5":  "badbot",
	"127.0.0.6":  "ftp",
	"127.0.0.7":  "imap",
	"127.0.0.8":  "ircbot",
	"127.0.0.9":  "mail",
	"127.0.0.10": "pop3",
	"127.0.0.11": "regbot",
	"127.0.0.12": "rfi-attack",
	"127.0.0.13": "sasl",
	"127.0.0.14": "ssh",
	"127.0.0.15": "w00tw00t",
	"127.0.0.16": "portflood",
	"127.0.0.17": "sql-injection",
	"127.0.0.18": "webmin",
	"127.0.0.19": "trigger-spam",
	"127.0.0.20": "manual",
	"127.0.0.21": "bruteforcelogin",
	"127.0.0.22": "mysql",
}

var blocklists4 = map[string]string{
	"blocklist.de": ".all.bl.blocklist.de",
	"cymru bogons": ".v4.fullbogons.cymru.com",
}

var (
	countDNSqueries, countDNSqueriesSuccess                   expvar.Int
	count4Packets, count4PacketsBlocked                       expvar.Int
	countCacheHitsBlock, countCacheHitsPass, countCacheMisses expvar.Int
)

func init() {

	m := expvar.NewMap("autoblock")
	m.Set("dnsQueries", &countDNSqueries)
	m.Set("dnsQueriesSuccess", &countDNSqueriesSuccess)
	m.Set("ipv4Packets", &count4Packets)
	m.Set("ipv4PacketsBlocked", &count4PacketsBlocked)
	m.Set("cacheHitsBlock", &countCacheHitsBlock)
	m.Set("cacheHitsPass", &countCacheHitsPass)
	m.Set("cacheHitsMisses", &countCacheMisses)
}

func main() {

	beStdErr := logging.NewLogBackend(os.Stderr, "", 0)
	beSyslog, _ := logging.NewSyslogBackend("autoblock")
	besysl := logging.AddModuleLevel(beSyslog)
	bestdErrl := logging.AddModuleLevel(beStdErr)
	level, err := logging.LogLevel("DEBUG")
	if err != nil {
		log.Fatal("Log level is not valid")
	}
	besysl.SetLevel(level, "")
	bestdErrl.SetLevel(level, "")
	logging.SetBackend(besysl, bestdErrl)

	log.Info("Starting...")

	go http.ListenAndServe(":8080", nil) // expvar serving, not for anything else

	lookupChannel := make(chan net.IP, 1000)

	// Create a cache with a default expiration time of 5 minutes, and which
	// purges expired items every 30 seconds
	// This makes some sense as DNS blocklist entries expire, and IP traffic per
	// entry would normally be low (few retries as they don't get a response)
	c := cache.New(5*time.Minute, 30*time.Second)

	// one worker per queue
	for i := 0; i < 4; i++ {
		go gofilter(i, lookupChannel, c)
	}
	golookup(lookupChannel, c)
}

func golookup(ch chan net.IP, c *cache.Cache) {
	for true {
		select {
		case ip := <-ch:
			_, found := c.Get(ip.String()) // check again, it may have been enqueued multiple times.
			if !found {
				result, _ := checkBlocklists(ip)
				if result != nil {
					c.Set(ip.String(), result, cache.DefaultExpiration)
				} else {
					c.Set(ip.String(), net.IPv4(0, 0, 0, 0), cache.DefaultExpiration) // cache as not blocked
				}
			}
		}
	}
}

func gofilter(i int, ch chan net.IP, c *cache.Cache) {
	nfq, err := netfilter.NewNFQueue(uint16(i), 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		log.Critical(err)
		os.Exit(1)
	}
	defer nfq.Close()
	packets := nfq.GetPackets()

	for true {
		select {
		case p := <-packets:

			if ipLayer := p.Packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				count4Packets.Add(1)
				ipl, _ := ipLayer.(*layers.IPv4)
				reason, found := c.Get(ipl.SrcIP.String())
				if found && !reason.(net.IP).Equal(net.IPv4(0, 0, 0, 0)) {
					countCacheHitsBlock.Add(1)
					p.SetVerdict(netfilter.NF_DROP)
					log.Info(ipl.SrcIP.String() + " to " + ipl.DstIP.String() + " blocked for reason: " + blockReason[reason.(net.IP).String()])
					count4PacketsBlocked.Add(1)
				} else {
					if !found {
						countCacheMisses.Add(1)
						ch <- ipl.SrcIP // enqueue for checks, out of this processing band
						log.Debug(ipl.SrcIP.String(), "passed okay")
					} else {
						countCacheHitsPass.Add(1)
					}
					p.SetVerdict(netfilter.NF_ACCEPT)
				}
			} else {
				log.Error("Not IP packet")
			}
		}
	}
}

func checkBlocklists(src net.IP) (net.IP, error) {
	log.Debug("checkBlocklist:", src)
	src4 := src.To4()
	if src4 == nil {
		return nil, errors.New("Not IPv4")
	}
	//reverse the address
	reversedaddr := fmt.Sprintf("%d.%d.%d.%d", src4[3], src4[2], src4[1], src4[0])

	for name, addr := range blocklists4 {
		ips, err := net.LookupIP(reversedaddr + addr)
		countDNSqueries.Add(1)
		if err != nil {
			log.Debug(src.String(), "not found in blocklist", name, "result:", err)

		} else {
			countDNSqueriesSuccess.Add(1)
			log.Debug(src.String(), "found in blocklist", name, "cause:", blockReason[ips[0].String()])
			return ips[0], err // only the first one required
		}
	}

	return nil, nil
}
