package asndb

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/btree"
)

const (
	asnURL    = "http://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN-CSV.zip"
	asnMd5URL = "http://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN-CSV.zip.md5"
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

// FromMaxMind loads data from maxmind and creates an ASNDB with this fresh data
func FromMaxMind() (*ASNDB, error) {
	// Get MD5 sum for tar.gz file
	resp, err := http.Get(asnMd5URL)
	if err != nil {
		return nil, err
	}

	md5Sum, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	// Load the tar.gz file
	resp, err = http.Get(asnURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Build the MD5 sum of the downloaded tar.gz
	hash := md5.New()
	if _, err := io.Copy(hash, bytes.NewReader(bodyData)); err != nil {
		return nil, err
	}
	if string(md5Sum) != hex.EncodeToString(hash.Sum(nil)) {
		return nil, fmt.Errorf("checksum mismatch: %s != %s", md5Sum, hash.Sum(nil))
	}

	// Copy the data to a temporary file for zip to be able to open it
	tmpF, err := ioutil.TempFile("/tmp", "asndb-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpF.Name())

	io.Copy(tmpF, bytes.NewReader(bodyData))
	tmpF.Close()

	zipReader, err := zip.OpenReader(tmpF.Name())
	if err != nil {
		return nil, err
	}
	defer zipReader.Close()

	buf := bytes.NewBufferString("")

	// find the data in the zip file
	for _, f := range zipReader.File {
		if strings.HasSuffix(f.Name, "GeoLite2-ASN-Blocks-IPv4.csv") || strings.HasSuffix(f.Name, "GeoLite2-ASN-Blocks-IPv6.csv") {
			asn, err := f.Open()
			if err != nil {
				return nil, err
			}

			io.Copy(buf, asn)
		}
	}

	if buf.Len() <= 0 {
		return nil, fmt.Errorf("not enough data")
	}

	// generate the tree
	tree, err := parseCSV(buf)
	if err != nil {
		return nil, err
	}

	return &ASNDB{db: tree}, nil
}

func parseCSV(reader io.Reader) (*btree.BTree, error) {
	csvr := csv.NewReader(reader)
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

	return tree, nil
}

// New creates a new ASN database. fname denotes the path to the Maxmind ASN CSV file
func New(fname string) (*ASNDB, error) {

	asnFile, err := os.Open(fname)
	if err != nil {
		return nil, fmt.Errorf("Failed to open ASN CSV file %s: %s", fname, err)
	}
	defer asnFile.Close()

	tree, err := parseCSV(asnFile)
	if err != nil {
		return nil, err
	}

	return &ASNDB{
		db: tree,
	}, nil
}
