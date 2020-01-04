// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"fmt"
	"strings"
)

// NetworkTraffic represents arbitrary network traffic that originates from a
// source and is addressed to a destination. The network traffic MAY or MAY NOT
// constitute a valid unicast, multicast, or broadcast network connection. This
// MAY also include traffic that is not established, such as a SYN flood.
//
// To allow for use cases where a source or destination address may be
// sensitive and not suitable for sharing, such as addresses that are internal
// to an organization’s network, the source and destination properties (Src and
// Dst, respectively) are defined as optional in the properties table below.
// However, a Network Traffic object MUST contain the protocols property and at
// least one of the Src or Dst properties and SHOULD contain the SrcPort and
// DstPort properties.
type NetworkTraffic struct {
	*STIXCyberObservableObject
	// Start specifies the date/time the network traffic was initiated, if
	// known.
	Start *Timestamp `json:"start,omitempty"`
	// End specifies the date/time the network traffic ended, if known.
	End *Timestamp `json:"end,omitempty"`
	// IsActive indicates whether the network traffic is still ongoing.
	IsActive bool `json:"is_active,omitempty"`
	// Src specifies the source of the network traffic, as a reference to a
	// Cyber-observable Object.
	Src Identifier `json:"src_ref,omitempty"`
	// Dst specifies the destination of the network traffic, as a reference to
	// a Cyber-observable Object.
	Dst Identifier `json:"dst_ref,omitempty"`
	// SrcPort specifies the source port used in the network traffic, as an
	// integer. The port value MUST be in the range of 0 - 65535.
	SrcPort int64 `json:"src_port,omitempty"`
	// DstPort specifies the destination port used in the network traffic, as
	// an integer. The port value MUST be in the range of 0 - 65535.
	DstPort int64 `json:"dst_port,omitempty"`
	// Protocols specifies the protocols observed in the network traffic, along
	// with their corresponding state. Protocols MUST be listed in low to high
	// order, from outer to inner in terms of packet encapsulation. That is,
	// the protocols in the outer level of the packet, such as IP, MUST be
	// listed first. The protocol names SHOULD come from the service names
	// defined in the Service Name column of the IANA Service Name and Port
	// Number Registry. In cases where there is variance in the name of a
	// network protocol not included in the IANA Registry, content producers
	// should exercise their best judgement, and it is recommended that
	// lowercase names be used for consistency with the IANA registry.
	//		Examples:
	// 		ipv4, tcp, http
	// 		ipv4, udp
	// 		ipv6, tcp, http
	// 		ipv6, tcp, ssl, https
	Protocols []string `json:"protocols"`
	// SrcByteCount specifies the number of bytes, as a positive integer, sent
	// from the source to the destination.
	SrcByteCount int64 `json:"src_byte_count,omitempty"`
	// DstByteCount specifies the number of bytes, as a positive integer, sent
	// from the destination to the source.
	DstByteCount int64 `json:"dst_byte_count,omitempty"`
	// SrcPackets specifies the number of packets, as a positive integer, sent
	// from the source to the destination.
	SrcPackets int64 `json:"src_packets,omitempty"`
	// DstPackets specifies the number of packets, as a positive integer, sent
	// from the destination to the source.
	DstPackets int64 `json:"dst_packets,omitempty"`
	// IPFIX specifies any IP Flow Information Export data for the traffic, as
	// a dictionary. Each key/value pair in the dictionary represents the
	// name/value of a single IPFIX element. Accordingly, each dictionary key
	// SHOULD be a case-preserved version of the IPFIX element name, e.g.,
	// octetDeltaCount. Each dictionary value MUST be either an integer or a
	// string, as well as a valid IPFIX property.
	IPFIX map[string]interface{} `json:"ipfix,omitempty"`
	// SrcPayload specifies the bytes sent from the source to the destination.
	SrcPayload Identifier `json:"src_payload_ref,omitempty"`
	// DstPayload specifies the bytes sent from the destination to the source.
	DstPayload Identifier `json:"dst_payload_ref,omitempty"`
	// Encapsulates links to other network-traffic objects encapsulated by this
	// network-traffic object.
	Encapsulates []Identifier `json:"encapsulates_refs,omitempty"`
	// Encapsulated links to another network-traffic object which encapsulates
	// this object.
	Encapsulated Identifier `json:"encapsulated_by_ref,omitempty"`
}

// HTTPRequestExtension returns the HTTP request extension for the object or
// nil.
func (n *NetworkTraffic) HTTPRequestExtension() *HTTPRequestExtension {
	data, ok := n.Extensions[ExtHTTPRequest]
	if !ok {
		return nil
	}
	var v HTTPRequestExtension
	json.Unmarshal(data, &v)
	return &v
}

// ICMPExtension returns the ICMP extension for the object or nil.
func (n *NetworkTraffic) ICMPExtension() *ICMPExtension {
	data, ok := n.Extensions[ExtICMP]
	if !ok {
		return nil
	}
	var v ICMPExtension
	json.Unmarshal(data, &v)
	return &v
}

// SocketExtension returns the socket extension for the object or nil.
func (n *NetworkTraffic) SocketExtension() *SocketExtension {
	data, ok := n.Extensions[ExtSocket]
	if !ok {
		return nil
	}
	var v SocketExtension
	json.Unmarshal(data, &v)
	return &v
}

// TCPExtension returns the tcp extension for the object or nil.
func (n *NetworkTraffic) TCPExtension() *TCPExtension {
	data, ok := n.Extensions[ExtTCP]
	if !ok {
		return nil
	}
	var v TCPExtension
	json.Unmarshal(data, &v)
	return &v
}

// NewNetworkTraffic creates a new NetworkTraffic object. A NetworkTraffic object MUST contain at least one
// of hashes or name.
func NewNetworkTraffic(proto []string, opts ...NetworkTrafficOption) (*NetworkTraffic, error) {
	if len(proto) == 0 {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeNetworkTraffic)
	obj := &NetworkTraffic{
		STIXCyberObservableObject: base,
		Protocols:                 proto,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}
	idContri := make([]string, 0, 5)
	if obj.Start != nil {
		idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.Start.String()))
	}
	if obj.Src != "" {
		idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.Src))
	}
	if obj.Dst != "" {
		idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.Dst))
	}
	if obj.SrcPort != 0 {
		idContri = append(idContri, fmt.Sprintf("%d", obj.SrcPort))
	}
	if obj.DstPort != 0 {
		idContri = append(idContri, fmt.Sprintf("%d", obj.DstPort))
	}
	idContri = append(idContri, fmt.Sprintf(`["%s"]`, strings.Join(obj.Protocols, `","`)))
	obj.ID = NewObservableIdenfier(fmt.Sprintf("[%s]", strings.Join(idContri, ",")), TypeNetworkTraffic)
	return obj, nil
}

// NetworkTrafficOption is an optional parameter when constructing a
// NetworkTraffic object.
type NetworkTrafficOption func(a *NetworkTraffic)

/*
	Base object options
*/

// NetworkTrafficOptionSpecVersion sets the STIX spec version.
func NetworkTrafficOptionSpecVersion(ver string) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.SpecVersion = ver
	}
}

// NetworkTrafficOptionObjectMarking sets the object marking attribute.
func NetworkTrafficOptionObjectMarking(om []Identifier) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.ObjectMarking = om
	}
}

// NetworkTrafficOptionGranularMarking sets the granular marking attribute.
func NetworkTrafficOptionGranularMarking(gm *GranularMarking) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.GranularMarking = gm
	}
}

// NetworkTrafficOptionDefanged sets the defanged attribute.
func NetworkTrafficOptionDefanged(b bool) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.Defanged = b
	}
}

// NetworkTrafficOptionExtension adds an extension.
func NetworkTrafficOptionExtension(name string, value interface{}) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		// Ignoring the error.
		obj.addExtension(name, value)
	}
}

/*
	NetworkTraffic object options
*/

// NetworkTrafficOptionStart sets the start attribute.
func NetworkTrafficOptionStart(s *Timestamp) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.Start = s
	}
}

// NetworkTrafficOptionEnd sets the end attribute.
func NetworkTrafficOptionEnd(s *Timestamp) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.End = s
	}
}

// NetworkTrafficOptionIsActive sets the is active attribute.
func NetworkTrafficOptionIsActive(s bool) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.IsActive = s
	}
}

// NetworkTrafficOptionSrc sets the src attribute.
func NetworkTrafficOptionSrc(s Identifier) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.Src = s
	}
}

// NetworkTrafficOptionDst sets the dst attribute.
func NetworkTrafficOptionDst(s Identifier) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.Dst = s
	}
}

// NetworkTrafficOptionSrcPort sets the src port attribute.
func NetworkTrafficOptionSrcPort(s int64) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.SrcPort = s
	}
}

// NetworkTrafficOptionDstPort sets the dst port attribute.
func NetworkTrafficOptionDstPort(s int64) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.DstPort = s
	}
}

// NetworkTrafficOptionSrcByteCount sets the src byte count attribute.
func NetworkTrafficOptionSrcByteCount(s int64) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.SrcByteCount = s
	}
}

// NetworkTrafficOptionDstByteCount sets the dst byte count attribute.
func NetworkTrafficOptionDstByteCount(s int64) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.DstByteCount = s
	}
}

// NetworkTrafficOptionSrcPackets sets the src packets attribute.
func NetworkTrafficOptionSrcPackets(s int64) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.SrcPackets = s
	}
}

// NetworkTrafficOptionDstPackets sets the dst packets attribute.
func NetworkTrafficOptionDstPackets(s int64) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.DstPackets = s
	}
}

// NetworkTrafficOptionIPFIX sets the IPFIX attribute.
func NetworkTrafficOptionIPFIX(s map[string]interface{}) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.IPFIX = s
	}
}

// NetworkTrafficOptionSrcPayload sets the src payload attribute.
func NetworkTrafficOptionSrcPayload(s Identifier) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.SrcPayload = s
	}
}

// NetworkTrafficOptionDstPayload sets the src payload attribute.
func NetworkTrafficOptionDstPayload(s Identifier) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.DstPayload = s
	}
}

// NetworkTrafficOptionEncapsulates sets the encapsulates attribute.
func NetworkTrafficOptionEncapsulates(s []Identifier) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.Encapsulates = s
	}
}

// NetworkTrafficOptionEncapsulated sets the encapsulated attribute.
func NetworkTrafficOptionEncapsulated(s Identifier) NetworkTrafficOption {
	return func(obj *NetworkTraffic) {
		obj.Encapsulated = s
	}
}

// HTTPRequestExtension specifies a default extension for capturing network
// traffic properties specific to HTTP requests.
type HTTPRequestExtension struct {
	// Method specifies the HTTP method portion of the HTTP request line, as a
	// lowercase string.
	Method string `json:"request_method"`
	// Value specifies the value (typically a resource path) portion of the
	// HTTP request line.
	Value string `json:"request_value"`
	// HTTPVersion specifies the HTTP version portion of the HTTP request line,
	// as a lowercase string.
	HTTPVersion string `json:"request_version,omitempty"`
	// Header specifies all of the HTTP header fields that may be found in the
	// HTTP client request, as a dictionary.
	Header map[string][]string `json:"request_header,omitempty"`
	// BodyLength specifies the length of the HTTP message body, if included,
	// in bytes.
	BodyLength int64 `json:"message_body_length,omitempty"`
	// Body specifies the data contained in the HTTP message body, if included.
	Body Identifier `json:"message_body_data_ref,omitempty"`
}

// ICMPExtension specifies a default extension for capturing network traffic
// properties specific to ICMP.
type ICMPExtension struct {
	// Type specifies the ICMP type byte.
	Type Hex `json:"icmp_type_hex"`
	// Code specifies the ICMP code byte.
	Code Hex `json:"icmp_code_hex"`
}

// SocketExtension sp
type SocketExtension struct {
	// AddressFamily specifies the address family (AF_*) that the socket is
	// configured for.
	AddressFamily SocketAddressFamily `json:"address_family"`
	// IsBlocking specifies whether the socket is in blocking mode.
	IsBlocking bool `json:"is_blocking,omitempty"`
	// IsListening specifies whether the socket is in listening mode.
	IsListening bool `json:"is_listening"`
	// Options specifies any options (SO_*) that may be used by the socket, as
	// a dictionary. Each key in the dictionary SHOULD be a case-preserved
	// version of the option name, e.g., SO_ACCEPTCONN. Each key value in the
	// dictionary MUST be the value for the corresponding options key.  Each
	// dictionary value MUST be an integer.  For SO_RCVTIMEO, SO_SNDTIMEO and
	// SO_LINGER the value represents the number of milliseconds.  If the
	// SO_LINGER key is present, it indicates that the SO_LINGER option is
	// active.
	Options map[string]int64 `json:"options,omitempty"`
	// SocketType specifies the type of the socket.
	SocketType SocketType `json:"socket_type,omitempty"`
	// SocketDescriptor specifies the socket file descriptor value associated
	// with the socket, as a non-negative integer.
	SocketDescriptor int64 `json:"socket_descriptor,omitempty"`
	// SocketHandle specifies the handle or inode value associated with the
	// socket.
	SocketHandle int64 `json:"socket_handle,omitempty"`
}

// SocketAddressFamily is a network socket address family type.
type SocketAddressFamily byte

// String returns the string representation of the type.
func (s SocketAddressFamily) String() string {
	return socketFamilyMap[s]
}

// MarshalJSON serializes the value to JSON.
func (s SocketAddressFamily) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, s.String())), nil
}

// UnmarshalJSON extracts the Socket family from the json data.
func (s *SocketAddressFamily) UnmarshalJSON(b []byte) error {
	if len(b) < 3 {
		*s = SocketFamilyUnknownValue
		return nil
	}
	t := string(b[1 : len(b)-1])
	for k, v := range socketFamilyMap {
		if v == t {
			*s = k
			return nil
		}
	}
	*s = SocketFamilyUnknownValue
	return nil
}

const (
	// SocketFamilyUnknownValue is an unknown socket family value.
	SocketFamilyUnknownValue SocketAddressFamily = iota
	// SocketFamilyUNSPEC specifies an unspecified address family.
	SocketFamilyUNSPEC
	// SocketFamilyINET specifies the IPv4 address family.
	SocketFamilyINET
	// SocketFamilyIPX specifies the IPX (Novell Internet Protocol) address
	// family.
	SocketFamilyIPX
	// SocketFamilyAPPLETALK specifies the APPLETALK DDP address family.
	SocketFamilyAPPLETALK
	// SocketFamilyNETBIOS specifies the NETBIOS address family.
	SocketFamilyNETBIOS
	// SocketFamilyINET6 specifies the IPv6 address family.
	SocketFamilyINET6
	// SocketFamilyIRDA specifies IRDA sockets.
	SocketFamilyIRDA
	// SocketFamilyBTH specifies BTH sockets.
	SocketFamilyBTH
)

var socketFamilyMap = map[SocketAddressFamily]string{
	SocketFamilyUnknownValue: "",
	SocketFamilyUNSPEC:       "AF_UNSPEC",
	SocketFamilyINET:         "AF_INET",
	SocketFamilyIPX:          "AF_IPX",
	SocketFamilyAPPLETALK:    "AF_APPLETALK",
	SocketFamilyNETBIOS:      "AF_NETBIOS",
	SocketFamilyINET6:        "AF_INET6",
	SocketFamilyIRDA:         "AF_IRDA",
	SocketFamilyBTH:          "AF_BTH",
}

// SocketType is a network socket type.
type SocketType byte

// String returns the string representation of the type.
func (s SocketType) String() string {
	return socketTypeMap[s]
}

// MarshalJSON serializes the value to JSON.
func (s SocketType) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, s.String())), nil
}

// UnmarshalJSON extracts the Socket type from the json data.
func (s *SocketType) UnmarshalJSON(b []byte) error {
	if len(b) < 3 {
		*s = SocketTypeUnknown
		return nil
	}
	t := string(b[1 : len(b)-1])
	for k, v := range socketTypeMap {
		if v == t {
			*s = k
			return nil
		}
	}
	*s = SocketTypeUnknown
	return nil
}

const (
	// SocketTypeUnknown is an unknown socket type value.
	SocketTypeUnknown SocketType = iota
	// SocketTypeStream specifies a pipe-like socket which operates over a
	// connection with a particular remote socket and transmits data reliably
	// as a stream of bytes.
	SocketTypeStream
	// SocketTypeDgram specifies a socket in which individually-addressed
	// packets are sent (datagram).
	SocketTypeDgram
	// SocketTypeRaw specifies raw sockets which allow new IP protocols to be
	// implemented in user space. A raw socket receives or sends the raw
	// datagram not including link level headers.
	SocketTypeRaw
	// SocketTypeRdm specifies a socket indicating a reliably-delivered
	// message.
	SocketTypeRdm
	// SocketTypeSeqpacket specifies a datagram congestion control protocol
	// socket.
	SocketTypeSeqpacket
)

var socketTypeMap = map[SocketType]string{
	SocketTypeUnknown:   "",
	SocketTypeStream:    "SOCK_STREAM",
	SocketTypeDgram:     "SOCK_DGRAM",
	SocketTypeRaw:       "SOCK_RAW",
	SocketTypeRdm:       "SOCK_RDM",
	SocketTypeSeqpacket: "SOCK_SEQPACKET",
}

// TCPExtension specifies a default extension for capturing network traffic
// properties specific to TCP.
type TCPExtension struct {
	// SrcFlags specifies the source TCP flags, as the union of all TCP flags
	// observed between the start of the traffic (as defined by the start
	// property) and the end of the traffic (as defined by the end property).
	SrcFlags Hex `json:"src_flags_hex,omitempty"`
	// DstFlags specifies the destination TCP flags, as the union of all TCP
	// flags observed between the start of the traffic (as defined by the start
	// property) and the end of the traffic (as defined by the end property).
	DstFlags Hex `json:"dst_flags_hex,omitempty"`
}
