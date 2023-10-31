package main

import (
	"flag"
	"fmt"
	_ "math/rand"
	"net"
	"strconv"
	"strings"
	_ "time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var CONFIG_SLD string
var CONFIG_NS string
var UniqueCounter uint32 = 0xfffffffa

func strategyMaker(name string, qtype uint16) int8 {
	var subdomain string
	labels := strings.Split(name, ".")
	if len(labels) >= 4 {
		subdomain = strings.ToLower(labels[len(labels)-4])
	}

	if qtype == dns.TypeA {
		if len(labels) == 4 && (subdomain == "ns1" || subdomain == "ns2") {
			return 0
		} else if strings.Contains(subdomain, "fwd") {
			return 1 // return rdns ip in cname
		} else if strings.Contains(subdomain, "rdns") {
			return 2 // return honey cname record
		} else if strings.Contains(subdomain, "honey") {
			return 3 // return timestamp in a record
		} else if strings.Contains(subdomain, "echo") {
			return 4 // basic echodns
		} else if strings.Contains(subdomain, "ttl") {
			return 5 // ttl test
		} else if strings.Contains(subdomain, "wrong-id") {
			return 6 // return response with wrong txid
		} else if strings.Contains(subdomain, "wrong-rec") {
			return 7 // return response with wrong records
		} else if strings.Contains(subdomain, "bailiwick") {
			return 8 // bailiwick verification
		} else if strings.Contains(subdomain, "cname-chain") {
			return 9 // unlimited ns chain
		} else if strings.Contains(subdomain, "ns-chain") {
			return 10 // unlimited cname chain
		} else if strings.Contains(subdomain, "attack") {
			return 11
		}
	}
	return -1
}

func InttoIPv4(n uint32) net.IP {
	b0 := (n >> 24) & 0xff
	b1 := (n >> 16) & 0xff
	b2 := (n >> 8) & 0xff
	b3 := n & 0xff
	return net.IPv4(byte(b0), byte(b1), byte(b2), byte(b3))
}

func TtlParser(domain string) uint32 {
	subdomain := strings.ToLower(strings.Split(domain, ".")[0])
	ttl, _ := strconv.Atoi(strings.Split(subdomain, "-")[0])
	return uint32(ttl)
}

func handleReflect(w dns.ResponseWriter, r *dns.Msg) {
	var (
		ip    net.IP
		port  int
		id    uint16
		name  string
		qtype uint16
	)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	m.Authoritative = true
	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		ip = addr.IP
		port = addr.Port
	}
	id = m.MsgHdr.Id
	name = m.Question[0].Name
	subdomain := strings.ToLower(strings.Split(name, ".")[0])
	qtype = m.Question[0].Qtype
	log.Log().Str("sip", ip.String()).Int64("port", int64(port)).Int64("id", int64(id)).Str("name", name).Int64("qtype", int64(qtype)).Msg("")
	//log.Printf("%v|%v|%v|%v|%v", ip, port, id, name, qtype)
	//fmt.Println(ip)
	//fmt.Println(name)
	//fmt.Println(qtype)
	switch strategyMaker(name, qtype) {
	case 1:
		cname_subdomain := "rdns-" + strings.Replace(ip.String(), ".", "-", -1)
		cname_fqdn := dns.Fqdn(cname_subdomain + "." + CONFIG_SLD)
		cname := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 14400},
			Target: cname_fqdn,
		}
		//fmt.Println(name+" "+cname_fqdn)
		m.Answer = append(m.Answer, cname)
	case 2:
		cname_fqdn := dns.Fqdn("honey." + CONFIG_SLD)
		cname := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 14400},
			Target: cname_fqdn,
		}
		//fmt.Println(cname_fqdn)
		m.Answer = append(m.Answer, cname)
	case 3:
		//time_str := strconv.FormatInt(time.Now().UnixMicro(), 10)
		//time_int, _ := strconv.Atoi(time_str[5 : len(time_str)-2])
		//time_int += rand.Intn(10000)
		UniqueCounter += 1
		timestamp := InttoIPv4(uint32(UniqueCounter))
		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 14400},
			A:   timestamp,
		}
		m.Answer = append(m.Answer, a)
	case 4:
		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   ip,
		}
		m.Answer = append(m.Answer, a)
	case 5:
		query_ttl := TtlParser(name)
		//fmt.Println(query_ttl)
		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: query_ttl},
			A:   ip,
		}
		m.Answer = append(m.Answer, a)
	case 6:
		m.MsgHdr.Id += 1
		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   ip,
		}
		m.Answer = append(m.Answer, a)
	case 7:
		wrong_answer := &dns.AAAA{
			Hdr:  dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP("fe80::7526:a2ae:a0b8:946d"),
		}
		m.Answer = append(m.Answer, wrong_answer)
	case 8:
		wrong_ns := &dns.NS{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  dns.Fqdn("dns.baidu.com"),
		}
		wrong_ns_ip := &dns.A{
			Hdr: dns.RR_Header{Name: "dns.baidu.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("159.75.200.247"),
		}
		m.Ns = append(m.Ns, wrong_ns)
		m.Extra = append(m.Extra, wrong_ns_ip)
	case 9:
		cname_target := ""
		labels := strings.Split(subdomain, "-")
		if labels[len(labels)-1] == "chain" {
			cname_target = subdomain + "-0"
		} else {
			iter_cnt, _ := strconv.Atoi(labels[len(labels)-1])
			iter_cnt += 1
			labels = append(labels[:len(labels)-1], strconv.Itoa(iter_cnt))
			cname_target = strings.Join(labels, "-")
			//cname_target = strings.Join([]string{labels[0], labels[1], strconv.Itoa(iter_cnt)}, "-")
		}
		cname_target = dns.Fqdn(cname_target + "." + CONFIG_SLD)
		cname_redir := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: cname_target,
		}
		m.Answer = append(m.Answer, cname_redir)
	case 10:
		ns_target := ""
		labels := strings.Split(subdomain, "-")
		if labels[len(labels)-1] == "chain" {
			ns_target = subdomain + "-0"
		} else {
			iter_cnt, _ := strconv.Atoi(labels[len(labels)-1])
			iter_cnt += 1
			labels = append(labels[:len(labels)-1], strconv.Itoa(iter_cnt))
			ns_target = strings.Join(labels, "-")
			//ns_target = strings.Join([]string{labels[0], labels[1], strconv.Itoa(iter_cnt)}, "-")
		}
		ns_target = dns.Fqdn(ns_target + "." + CONFIG_SLD)
		ns_delegation := &dns.NS{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  ns_target,
		}
		m.Ns = append(m.Ns, ns_delegation)
	case 11:
		ns_record := &dns.NS{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  "shiyan7.jthmfgz.icu.",
		}
		m.Ns = append(m.Ns, ns_record)
	case 0:
		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   net.ParseIP(CONFIG_NS),
		}
		m.Answer = append(m.Answer, a)
	case -1:
		m.MsgHdr.Rcode = dns.RcodeNameError
	}
	w.WriteMsg(m)
}

func main() {
	flag.StringVar(&CONFIG_NS, "ns", "159.75.200.247", "configure nameserver ip for echo dns zone")
	flag.StringVar(&CONFIG_SLD, "sld", "", "configure sld for echo dns server")
	flag.Parse()
	if CONFIG_SLD == "" {
		panic("Please configure the SLD for the echo dns server!\n")
	}
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	dns.HandleFunc(dns.Fqdn(CONFIG_SLD), handleReflect)
	server := &dns.Server{Addr: ":53", Net: "udp"}
	if err := server.ListenAndServe(); err != nil {
		fmt.Println("Failed to set up dns server!")
		panic(err)
	}
}
