// Copyright (c) 2016 shawn1m. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

// Package common provides common functions.
package common

import (
	"net"
	"regexp"
	"strings"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

type IPNetList []*net.IPNet

func (l IPNetList) Len() int {
	return len(l)
}

func (l IPNetList) Less(i, j int) bool {
	// sort by IP
	return IPComapre(l[i].IP, l[j].IP) == -1
}

func (l IPNetList) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

func IPComapre(ip1, ip2 net.IP) int {
	// The result will be 0 if ip == ip2, -1 if ip < ip2, and +1 if ip > ip2.
	var ipCmp1, ipCmp2 net.IP
	if len(ip1) == len(ip2) {
		ipCmp1, ipCmp2 = ip1, ip2
	}
	if len(ip1) == net.IPv4len && len(ip2) == net.IPv6len {
		ipCmp1 = make(net.IP, net.IPv6len)
		ipCmp1[10] = 255
		ipCmp1[11] = 255
		copy(ipCmp1[12:], ip1)
		ipCmp2 = ip2
	}
	if len(ip1) == net.IPv6len && len(ip2) == net.IPv4len {
		ipCmp2 = make(net.IP, net.IPv6len)
		ipCmp2[10] = 255
		ipCmp2[11] = 255
		copy(ipCmp2[12:], ip2)
		ipCmp1 = ip1
	}
	for k := range ipCmp1 {
		if ipCmp1[k] < ipCmp2[k] {
			return -1
		}
		if ipCmp1[k] == ipCmp2[k] {
			continue
		}
		return +1
	}
	return 0
}

func (l IPNetList) BinaryContains(ip net.IP) *net.IPNet {
	// IPNetList must sorted, and bit-aligned
	// The complexity is O(logn).
	var (
		start = 0
		end   = len(l) - 1
		mid   = 0
	)
	for {
		mid = (start + end) / 2
		// log.Debugln(start, end, mid, l[mid].IP, ip, IPComapre(l[mid].IP, ip))
		if l[mid].Contains(ip) {
			return l[mid]
		} else if IPComapre(l[mid].IP, ip) == -1 {
			start = mid + 1
		} else {
			end = mid - 1
		}

		if start > end {
			return nil
		}
	}
}

var ReservedIPNetworkList = getReservedIPNetworkList()

func IsIPMatchList(ip net.IP, ipNetList IPNetList, isLog bool, name string) bool {
	if ipNetList != nil {
		if ipNet := ipNetList.BinaryContains(ip); ipNet != nil {
			if isLog {
				log.Debugf("Matched: IP network %s %s %s", name, ip.String(), ipNet.String())
			}
			return true
		}
	} else {
		log.Debug("IP network list is nil, not checking")
	}

	return false
}

func IsDomainMatchRule(pattern string, domain string) bool {
	matched, err := regexp.MatchString(pattern, domain)
	if err != nil {
		log.Warnf("Error matching domain %s with pattern %s: %s", domain, pattern, err)
	}
	return matched
}

func HasAnswer(m *dns.Msg) bool { return m != nil && len(m.Answer) != 0 }

func HasSubDomain(s string, sub string) bool {
	return strings.HasSuffix(sub, "."+s) || s == sub
}

func getReservedIPNetworkList() IPNetList {
	return IPNetList{
		&net.IPNet{ // 127.0.0.0/8
			IP:   net.IP{127, 0, 0, 0},
			Mask: net.IPMask{255, 0, 0, 0},
		},
		&net.IPNet{ // 10.0.0.0/8
			IP:   net.IP{10, 0, 0, 0},
			Mask: net.IPMask{255, 0, 0, 0},
		},
		&net.IPNet{ // 172.16.0.0/12
			IP:   net.IP{172, 16, 0, 0},
			Mask: net.IPMask{255, 240, 0, 0},
		},
		&net.IPNet{ // 192.168.0.0/16
			IP:   net.IP{192, 168, 0, 1},
			Mask: net.IPMask{255, 255, 0, 0},
		},
		&net.IPNet{ // 100.64.0.0/10
			IP:   net.IP{100, 64, 0, 1},
			Mask: net.IPMask{255, 192, 0, 0},
		},
	}
}

func FindRecordByType(msg *dns.Msg, t uint16) string {
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == t {
			items := strings.SplitN(rr.String(), "\t", 5)
			return items[4]
		}
	}

	return ""
}

func SetMinimumTTL(msg *dns.Msg, minimumTTL uint32) {
	if minimumTTL == 0 {
		return
	}
	for _, a := range msg.Answer {
		if a.Header().Ttl < minimumTTL {
			a.Header().Ttl = minimumTTL
		}
	}
}

func SetTTLByMap(msg *dns.Msg, domainTTLMap map[string]uint32) {
	if len(domainTTLMap) == 0 {
		return
	}
	for _, a := range msg.Answer {
		name := a.Header().Name[:len(a.Header().Name)-1]
		for k, v := range domainTTLMap {
			if IsDomainMatchRule(k, name) {
				a.Header().Ttl = v
			}
		}
	}
}
