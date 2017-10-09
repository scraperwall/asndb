package asndb

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"

	"github.com/google/btree"
)

// ASNDB contains a b-tree of ASNs
type ASNDB struct {
	db *btree.BTree
}

// Lookup returns the ASN struct of the network that contains ip
func (a *ASNDB) Lookup(ip net.IP) *ASN {
	var asn *ASN

	ipNorm := ip.To16()
	dummy := ASN{
		To: &ipNorm,
	}

	a.db.AscendGreaterOrEqual(&dummy, func(item btree.Item) bool {
		asn = item.(*ASN)

		return false
	})

	return asn
}

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
		return nil, fmt.Errorf("CIDR parse error for %s: %s\n", cidr, err)
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

// New creates a new ASN database. fname denotes the path to the Maxmind ASN CSV file
func New(fname string) (*ASNDB, error) {

	asnFile, err := os.Open(fname)
	if err != nil {
		return nil, fmt.Errorf("Failed to open ASN CSV file %s: %s", fname, err)
	}
	defer asnFile.Close()

	csvr := csv.NewReader(asnFile)
	numMatch := regexp.MustCompile(`^[0-9a-fA-F]+[\.:]`)

	tree := btree.New(8)

	for {
		record, err := csvr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		// ignore the header and anything that doesn't look like an IP
		if !numMatch.MatchString(record[0]) {
			continue
		}

		a, err := NewASN(record[0], record[1], record[2])
		if err != nil {
			return nil, err
		}

		tree.ReplaceOrInsert(a)
	}

	return &ASNDB{
		db: tree,
	}, nil
}
