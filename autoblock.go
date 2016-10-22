package main

import (
	"errors"
	"fmt"
	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket/layers"
	"github.com/op/go-logging"
	"github.com/patrickmn/go-cache"
	"net"
	"os"
	"time"
)

var log = logging.MustGetLogger("autoblock")

var blockReason = map[string]string{
	"127.0.0.2":  "amavis",
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

func main() {

	be, _ := logging.NewSyslogBackend("autoblock")
	bel := logging.AddModuleLevel(be)
	bel.SetLevel(logging.DEBUG, "")
	log.SetBackend(bel)

	log.Info("Starting...")

	lookupChannel := make(chan net.IP, 1000)

	// Create a cache with a default expiration time of 5 minutes, and which
	// purges expired items every 30 seconds
	c := cache.New(5*time.Minute, 30*time.Second)

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
				result, _ := checkBlocklist(ip)
				if result != nil {
					c.Set(ip.String(), result, cache.DefaultExpiration)
				} else {
					c.Set(ip.String(), net.IPv4(0, 0, 0, 0), cache.DefaultExpiration)
				}
			}
		}
	}
}

func gofilter(i int, ch chan net.IP, c *cache.Cache) {
	nfq, err := netfilter.NewNFQueue(uint16(i), 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer nfq.Close()
	packets := nfq.GetPackets()

	for true {
		select {
		case p := <-packets:

			if ipLayer := p.Packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ipl, _ := ipLayer.(*layers.IPv4)
				reason, found := c.Get(ipl.SrcIP.String())
				if found && !reason.(net.IP).Equal(net.IPv4(0, 0, 0, 0)) {
					p.SetVerdict(netfilter.NF_DROP)
					log.Info(ipl.SrcIP.String() + " to " + ipl.DstIP.String() + " blocked for reason: " + blockReason[reason.(net.IP).String()])
				} else {
					if !found {
						ch <- ipl.SrcIP
						fmt.Println(ipl.SrcIP.String(), "passed okay")
					}
					p.SetVerdict(netfilter.NF_ACCEPT)
				}
			} else {
				fmt.Println("Not IP packet")
			}
		}
	}
}

func checkBlocklist(src net.IP) (net.IP, error) {
	fmt.Println("checkBlocklist:", src)
	src4 := src.To4()
	if src4 == nil {
		return nil, errors.New("Not IPv4")
	}
	//reverse the address
	blocklistedhost := fmt.Sprintf("%d.%d.%d.%d.%s", src4[3], src4[2], src4[1], src4[0], "all.bl.blocklist.de")
	ips, err := net.LookupIP(blocklistedhost)

	if err != nil {
		fmt.Println(src.String(), "not found in blocklist", err)
		return nil, err
	} else {
		fmt.Println(src.String(), "found in blocklist:", blockReason[ips[0].String()])
		return ips[0], err // only the first one required
	}

	blocklistedhost = ".v4.fullbogons.cymru.com"
	return nil, err
}
