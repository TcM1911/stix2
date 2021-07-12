// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import "fmt"

// IPv4Address represents one or more IPv4 addresses expressed using CIDR
// notation.
type IPv4Address struct {
	STIXCyberObservableObject
	// Value specifies the values of one or more IPv4 addresses expressed using
	// CIDR notation. If a given IPv4Address object represents a single IPv4
	// address, the CIDR /32 suffix MAY be omitted. Example: 10.2.4.5/24
	Value string `json:"value"`
	// ResolvesTo specifies a list of references to one or more Layer 2 Media
	// Access Control (MAC) addresses that the IPv4 address resolves to.
	ResolvesTo []Identifier `json:"resolves_to_refs,omitempty"`
	// BelongsTo specifies a list of references to one or more autonomous
	// systems (AS) that the IPv4 address belongs to.
	BelongsTo []Identifier `json:"belongs_to_refs,omitempty"`
}

// AddResolvesTo describes that this IPv4Address resolves to one or more Layer
// 2 Media Access Control (MAC) addresses.
func (c *IPv4Address) AddResolvesTo(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeMACAddress) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeResolvesTo, c.ID, id, opts...)
}

// AddBelongsTo describes that this IPv4 Address belongs to one or more
// autonomous systems (AS).
func (c *IPv4Address) AddBelongsTo(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeAutonomousSystem) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeBelongsTo, c.ID, id, opts...)
}

// NewIPv4Address creates a new IPv4Address object.
func NewIPv4Address(value string, opts ...STIXOption) (*IPv4Address, error) {
	if value == "" {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeIPv4Addr)
	obj := &IPv4Address{
		STIXCyberObservableObject: base,
		Value:                     value,
	}

	err := applyOptions(obj, opts)
	obj.ID = NewObservableIdentifier(fmt.Sprintf("[\"%s\"]", value), TypeIPv4Addr)
	return obj, err
}

// IPv6Address represents one or more IPv6 addresses expressed using CIDR
// notation.
type IPv6Address struct {
	STIXCyberObservableObject
	// Value specifies the values of one or more IPv6 addresses expressed using
	// CIDR notation. If a given IPv6Address object represents a single IPv6
	// address, the CIDR /128 suffix MAY be omitted.
	Value string `json:"value"`
	// ResolvesTo specifies a list of references to one or more Layer 2 Media
	// Access Control (MAC) addresses that the IPv6 address resolves to.
	ResolvesTo []Identifier `json:"resolves_to_refs,omitempty"`
	// BelongsTo specifies a list of references to one or more autonomous
	// systems (AS) that the IPv6 address belongs to.
	BelongsTo []Identifier `json:"belongs_to_refs,omitempty"`
}

// AddResolvesTo describes that this IPv6Address resolves to one or more Layer
// 2 Media Access Control (MAC) addresses.
func (c *IPv6Address) AddResolvesTo(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeMACAddress) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeResolvesTo, c.ID, id, opts...)
}

// AddBelongsTo describes that this IPv6 Address belongs to one or more
// autonomous systems (AS).
func (c *IPv6Address) AddBelongsTo(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeAutonomousSystem) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeBelongsTo, c.ID, id, opts...)
}

// NewIPv6Address creates a new IPv6Address object.
func NewIPv6Address(value string, opts ...STIXOption) (*IPv6Address, error) {
	if value == "" {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeIPv6Addr)
	obj := &IPv6Address{
		STIXCyberObservableObject: base,
		Value:                     value,
	}

	err := applyOptions(obj, opts)
	obj.ID = NewObservableIdentifier(fmt.Sprintf("[\"%s\"]", value), TypeIPv6Addr)
	return obj, err
}
