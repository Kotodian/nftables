package expr

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestXfrm(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		xfrm Xfrm
	}{
		{
			name: "ipsec out ip daddr",
			xfrm: Xfrm{
				Register: 1,
				Key:      XfrmKeyDaddrIP4,
				Dir:      XfrmDirOut,
				Spnum:    0,
			},
		},
		{
			name: "ipsec in ip saddr",
			xfrm: Xfrm{
				Register: 1,
				Key:      XfrmKeySaddrIP4,
				Dir:      XfrmDirIn,
				Spnum:    0,
			},
		},
		{
			name: "ipsec out reqid",
			xfrm: Xfrm{
				Register: 1,
				Key:      XfrmKeyReqid,
				Dir:      XfrmDirOut,
				Spnum:    0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nXfrm := Xfrm{}
			data, err := tt.xfrm.marshal(0)
			if err != nil {
				t.Fatalf("marshal error: %+v", err)
			}
			ad, err := netlink.NewAttributeDecoder(data)
			if err != nil {
				t.Fatalf("NewAttributeDecoder() error: %+v", err)
			}
			ad.ByteOrder = binary.BigEndian
			for ad.Next() {
				if ad.Type() == unix.NFTA_EXPR_DATA {
					if err := nXfrm.unmarshal(0, ad.Bytes()); err != nil {
						t.Errorf("unmarshal error: %+v", err)
						break
					}
				}
			}
			if !reflect.DeepEqual(tt.xfrm, nXfrm) {
				t.Fatalf("original %+v and recovered %+v Xfrm structs are different", tt.xfrm, nXfrm)
			}
		})
	}
}
