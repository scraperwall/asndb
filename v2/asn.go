package asndb

import (
	"bytes"
	"fmt"
	"net"
	"strconv"

	"github.com/google/btree"
)

// ASN contains information about a netblock
type ASN struct {
	Network      *net.IPNet `json:"network"`
	From         *net.IP    `json:"from"`
	To           *net.IP    `json:"to"`
	Cidr         string     `json:"cidr"`
	ASN          int        `json:"asn"`
	Organization string     `json:"organization"`
}

// NewASN creates a new ASN struct based on cidr, asnr and org
func NewASN(cidr string, asnr string, org string) (*ASN, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("cidr parse error for %s: %s", cidr, err)
	}

	asn, err := strconv.Atoi(asnr)
	if err != nil {
		return nil, fmt.Errorf("ASN parse error for %s: %s", asnr, err)
	}

	ip := network.IP.To16()
	mask := net.IPMask(make([]byte, net.IPv6len))

	if ip.To4() != nil {
		for i := 0; i < net.IPv6len-net.IPv4len; i++ {
			mask[i] = 0xff
		}

		for i, val := range network.Mask {
			mask[i+net.IPv6len-net.IPv4len] = val
		}
	} else {
		mask = network.Mask
	}

	firstIP := net.IP(make([]byte, 16))
	lastIP := net.IP(make([]byte, 16))

	for i := range ip {
		firstIP[i] = ip[i] & mask[i]
		lastIP[i] = ip[i] | ^mask[i]
	}

	return &ASN{
		Network:      network,
		Organization: org,
		ASN:          asn,
		From:         &firstIP,
		To:           &lastIP,
		Cidr:         cidr,
	}, nil
}

// Less determines whether a is lexicographically smaller than bt
func (a *ASN) Less(bt btree.Item) bool {
	b := bt.(*ASN)

	return bytes.Compare(*a.To, *b.To) < 0
}
