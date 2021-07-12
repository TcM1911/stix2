// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkTraffic(t *testing.T) {
	assert := assert.New(t)

	val := []string{"ipv4", "tcp", "ssl", "https"}
	ts := &Timestamp{time.Now()}
	testInt := int64(42)
	ref := Identifier("ref")
	ipfix := map[string]interface{}{}

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewNetworkTraffic([]string{}, nil)
		assert.Nil(obj)
		assert.Equal(ErrInvalidParameter, err)
	})

	t.Run("with_property", func(t *testing.T) {
		obj, err := NewNetworkTraffic(val, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("payload_with_options", func(t *testing.T) {
		marking := make([]*GranularMarking, 0)
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []STIXOption{
			OptionGranularMarking(marking),
			OptionObjectMarking(objmark),
			OptionSpecVersion(specVer),
			OptionDefanged(true),
			//
			OptionStart(ts),
			OptionEnd(ts),
			OptionIsActive(true),
			OptionSrc(ref),
			OptionDst(ref),
			OptionSrcPort(testInt),
			OptionDstPort(testInt),
			OptionSrcByteCount(testInt),
			OptionDstByteCount(testInt),
			OptionSrcPackets(testInt),
			OptionDstPackets(testInt),
			OptionSrcPayload(ref),
			OptionDstPayload(ref),
			OptionEncapsulates([]Identifier{ref}),
			OptionEncapsulated(ref),
			OptionIPFIX(ipfix),
		}
		obj, err := NewNetworkTraffic(val, opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.Equal(specVer, obj.SpecVersion)
		assert.True(obj.Defanged)

		assert.Equal(val, obj.Protocols)
		assert.Equal(ts, obj.Start)
		assert.Equal(ts, obj.End)
		assert.True(obj.IsActive)
		assert.Equal(ref, obj.Src)
		assert.Equal(ref, obj.Dst)
		assert.Equal(testInt, obj.SrcPort)
		assert.Equal(testInt, obj.DstPort)
		assert.Equal(testInt, obj.SrcByteCount)
		assert.Equal(testInt, obj.DstByteCount)
		assert.Equal(testInt, obj.SrcPackets)
		assert.Equal(testInt, obj.DstPackets)
		assert.Equal(ref, obj.SrcPayload)
		assert.Equal(ref, obj.DstPayload)
		assert.Contains(obj.Encapsulates, ref)
		assert.Equal(ref, obj.Encapsulated)
		assert.Equal(ipfix, obj.IPFIX)
	})

	t.Run("id-generation", func(t *testing.T) {
		tme, err := time.Parse(time.RFC3339Nano, "2016-01-20T12:31:12.123Z")
		require.NoError(t, err)
		ts := &Timestamp{tme}
		tests := []struct {
			start     *Timestamp
			src       string
			dst       string
			srcPort   int64
			dstPort   int64
			protocols []string
			id        string
		}{
			{
				nil,
				"",
				"mac-addr--08900593-0265-52fc-93c0-5b4a942f5887",
				0,
				0,
				val,
				"network-traffic--bdf93ebb-19c1-58db-9d4d-2375e5b0d4da",
			},
			{
				nil,
				"mac-addr--08900593-0265-52fc-93c0-5b4a942f5888",
				"mac-addr--08900593-0265-52fc-93c0-5b4a942f5887",
				0,
				0,
				val,
				"network-traffic--f0d9b382-d3dd-5a34-bca5-a9d985971248",
			},
			{
				nil,
				"mac-addr--08900593-0265-52fc-93c0-5b4a942f5888",
				"mac-addr--08900593-0265-52fc-93c0-5b4a942f5887",
				0,
				int64(443),
				val,
				"network-traffic--5346eef2-e610-5cff-8d69-051731f9d256",
			},
			{
				nil,
				"mac-addr--08900593-0265-52fc-93c0-5b4a942f5888",
				"mac-addr--08900593-0265-52fc-93c0-5b4a942f5887",
				int64(1443),
				int64(443),
				val,
				"network-traffic--e85613bc-7c91-54f2-ac60-a424b9db67fe",
			},
			{
				ts,
				"mac-addr--08900593-0265-52fc-93c0-5b4a942f5888",
				"mac-addr--08900593-0265-52fc-93c0-5b4a942f5887",
				int64(1443),
				int64(443),
				val,
				"network-traffic--57c9c61e-d5ed-5ea5-91b4-c46d45fd1efb",
			},
			// {nil, "", "", 0, 0, []string{}, ""},
		}
		for _, test := range tests {
			opts := make([]STIXOption, 0, 5)
			if test.start != nil {
				opts = append(opts, OptionStart(test.start))
			}
			if test.src != "" {
				opts = append(opts, OptionSrc(Identifier(test.src)))
			}
			if test.dst != "" {
				opts = append(opts, OptionDst(Identifier(test.dst)))
			}
			if test.srcPort != 0 {
				opts = append(opts, OptionSrcPort(test.srcPort))
			}
			if test.dstPort != 0 {
				opts = append(opts, OptionDstPort(test.dstPort))
			}
			obj, err := NewNetworkTraffic(test.protocols, opts...)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	t.Run("http-extension", func(t *testing.T) {
		ext := &HTTPRequestExtension{Method: "get", Value: "/", HTTPVersion: "1.1"}
		f, _ := NewNetworkTraffic(val, OptionExtension(ExtHTTPRequest, ext))
		assert.Len(f.Extensions, 1)
		stored := f.HTTPRequestExtension()
		assert.Equal(ext, stored)
	})

	t.Run("http-extension-nil", func(t *testing.T) {
		f, _ := NewNetworkTraffic(val)
		assert.Len(f.Extensions, 0)
		stored := f.HTTPRequestExtension()
		assert.Nil(stored)
	})

	t.Run("icmp-extension", func(t *testing.T) {
		ext := &ICMPExtension{Type: Hex("08"), Code: Hex("00")}
		f, _ := NewNetworkTraffic(val, OptionExtension(ExtICMP, ext))
		assert.Len(f.Extensions, 1)
		stored := f.ICMPExtension()
		assert.Equal(ext, stored)
	})

	t.Run("icmp-extension-nil", func(t *testing.T) {
		f, _ := NewNetworkTraffic(val)
		assert.Len(f.Extensions, 0)
		stored := f.ICMPExtension()
		assert.Nil(stored)
	})

	t.Run("socket-extension", func(t *testing.T) {
		ext := &SocketExtension{AddressFamily: SocketFamilyINET, SocketType: SocketTypeRaw}
		f, _ := NewNetworkTraffic(val, OptionExtension(ExtSocket, ext))
		assert.Len(f.Extensions, 1)
		stored := f.SocketExtension()
		assert.Equal(ext, stored)
	})

	t.Run("socket-extension-nil", func(t *testing.T) {
		f, _ := NewNetworkTraffic(val)
		assert.Len(f.Extensions, 0)
		stored := f.SocketExtension()
		assert.Nil(stored)
	})

	t.Run("unknown-socket-family", func(t *testing.T) {
		ext := &SocketExtension{AddressFamily: SocketFamilyUnknownValue, SocketType: SocketTypeUnknown}
		f, err := NewNetworkTraffic(val, OptionExtension(ExtSocket, ext))
		assert.NoError(err)
		assert.Len(f.Extensions, 1)
		stored := f.SocketExtension()
		assert.Equal(ext, stored)
	})

	t.Run("socket-extenstion-json", func(t *testing.T) {
		ext := &SocketExtension{
			AddressFamily: SocketFamilyUnknownValue,
			SocketType:    SocketTypeUnknown,
			IsBlocking:    true,
		}
		data, err := json.Marshal(ext)
		assert.NoError(err)
		var un *SocketExtension
		err = json.Unmarshal(data, &un)
		assert.NoError(err)
		assert.Equal(ext, un)
	})

	t.Run("tcp-extension", func(t *testing.T) {
		ext := &TCPExtension{SrcFlags: Hex("FF")}
		f, _ := NewNetworkTraffic(val, OptionExtension(ExtTCP, ext))
		assert.Len(f.Extensions, 1)
		stored := f.TCPExtension()
		assert.Equal(ext, stored)
	})

	t.Run("socket-extension-nil", func(t *testing.T) {
		f, _ := NewNetworkTraffic(val)
		assert.Len(f.Extensions, 0)
		stored := f.TCPExtension()
		assert.Nil(stored)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "network-traffic",
  "spec_version": "2.1",
  "id": "network-traffic--2568d22a-8998-58eb-99ec-3c8ca74f527d",
  "src_ref": "ipv4-addr--4d22aae0-2bf9-5427-8819-e4f6abf20a53",
  "dst_ref": "ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd",
  "protocols": [
    "tcp"
  ]
}`)
		var obj *NetworkTraffic
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("network-traffic--2568d22a-8998-58eb-99ec-3c8ca74f527d"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeNetworkTraffic, obj.Type)
		assert.Equal(Identifier("ipv4-addr--4d22aae0-2bf9-5427-8819-e4f6abf20a53"), obj.Src)
		assert.Equal(Identifier("ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd"), obj.Dst)
		assert.Equal("tcp", obj.Protocols[0])
	})

	t.Run("parse_json_pe", func(t *testing.T) {
		data := []byte(`{
  "type": "network-traffic",
  "spec_version": "2.1",
  "id": "network-traffic--c95e972a-20a4-5307-b00d-b8393faf02c5",
  "src_ref": "ipv4-addr--4d22aae0-2bf9-5427-8819-e4f6abf20a53",
  "src_port": 223,
  "protocols": [
    "ip",
    "tcp"
  ],
  "extensions": {
    "socket-ext": {
      "is_listening": true,
      "address_family": "AF_INET",
      "socket_type": "SOCK_STREAM"
    }
  }
}`)
		var obj *NetworkTraffic
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("network-traffic--c95e972a-20a4-5307-b00d-b8393faf02c5"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeNetworkTraffic, obj.Type)
		ext := obj.SocketExtension()
		assert.Equal(SocketFamilyINET, ext.AddressFamily)
		assert.Equal(SocketTypeStream, ext.SocketType)
		assert.True(ext.IsListening)
	})

	t.Run("socket-type-unmarshal-short", func(t *testing.T) {
		d1 := []byte("A")
		var typ SocketType
		ptr := &typ
		err := ptr.UnmarshalJSON(d1)
		assert.NoError(err)
		assert.Equal(SocketTypeUnknown, typ)
	})

	t.Run("socket-type-unmarshal-invalid-key", func(t *testing.T) {
		d1 := []byte("AAAAAAA")
		var typ SocketType
		ptr := &typ
		err := ptr.UnmarshalJSON(d1)
		assert.NoError(err)
		assert.Equal(SocketTypeUnknown, typ)
	})

	t.Run("socket-family-unmarshal-invalid-key", func(t *testing.T) {
		d1 := []byte("AAAAAAA")
		var typ SocketAddressFamily
		ptr := &typ
		err := ptr.UnmarshalJSON(d1)
		assert.NoError(err)
		assert.Equal(SocketFamilyUnknownValue, typ)
	})
}
