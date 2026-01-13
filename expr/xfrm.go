// Copyright 2018 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package expr

import (
	"encoding/binary"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// XFRM expression attribute types
// Reference: /usr/include/linux/netfilter/nf_tables.h
const (
	NFTA_XFRM_DREG  = 1
	NFTA_XFRM_KEY   = 2
	NFTA_XFRM_DIR   = 3
	NFTA_XFRM_SPNUM = 4
)

// XfrmKey specifies what XFRM data to retrieve
type XfrmKey uint32

// Possible XfrmKey values
const (
	XfrmKeyUnspec   XfrmKey = 0
	XfrmKeyDaddrIP4 XfrmKey = 1 // Destination address (IPv4)
	XfrmKeyDaddrIP6 XfrmKey = 2 // Destination address (IPv6)
	XfrmKeySaddrIP4 XfrmKey = 3 // Source address (IPv4)
	XfrmKeySaddrIP6 XfrmKey = 4 // Source address (IPv6)
	XfrmKeyReqid    XfrmKey = 5 // Request ID
	XfrmKeySpi      XfrmKey = 6 // Security Parameter Index
)

// XfrmDir specifies the direction for XFRM matching
type XfrmDir uint8

// Possible XfrmDir values
const (
	XfrmDirIn  XfrmDir = 0 // Inbound (decrypted packets)
	XfrmDirOut XfrmDir = 1 // Outbound (to be encrypted)
	XfrmDirFwd XfrmDir = 2 // Forwarded
)

// Xfrm implements the nftables "xfrm" (ipsec) expression for matching IPsec traffic.
// This allows rules like: ipsec out ip daddr 10.10.0.40
// Reference: https://thermalcircle.de/doku.php?id=blog:linux:nftables_demystifying_ipsec_expressions
type Xfrm struct {
	Register uint32  // Destination register to store the result
	Key      XfrmKey // What XFRM data to retrieve (address, reqid, spi)
	Dir      XfrmDir // Direction (in/out/fwd)
	Spnum    uint32  // Index in secpath array (usually 0)
}

func (e *Xfrm) marshal(fam byte) ([]byte, error) {
	data, err := e.marshalData(fam)
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("xfrm\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
}

func (e *Xfrm) marshalData(fam byte) ([]byte, error) {
	// Build attributes in the order kernel expects
	attrs := []netlink.Attribute{
		{Type: NFTA_XFRM_DREG, Data: binaryutil.BigEndian.PutUint32(e.Register)},
		{Type: NFTA_XFRM_KEY, Data: binaryutil.BigEndian.PutUint32(uint32(e.Key))},
		{Type: NFTA_XFRM_DIR, Data: []byte{byte(e.Dir)}},
		{Type: NFTA_XFRM_SPNUM, Data: binaryutil.BigEndian.PutUint32(e.Spnum)},
	}
	return netlink.MarshalAttributes(attrs)
}

func (e *Xfrm) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case NFTA_XFRM_DREG:
			e.Register = ad.Uint32()
		case NFTA_XFRM_KEY:
			e.Key = XfrmKey(ad.Uint32())
		case NFTA_XFRM_DIR:
			e.Dir = XfrmDir(ad.Bytes()[0])
		case NFTA_XFRM_SPNUM:
			e.Spnum = ad.Uint32()
		}
	}
	return ad.Err()
}
