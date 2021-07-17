// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import "fmt"

// DomainName object represents the properties of a network domain name.
type DomainName struct {
	STIXCyberObservableObject
	// Value specifies the value of the domain name. The value of this property
	// MUST conform to RFC1034, and each domain and sub-domain contained within
	// the domain name MUST conform to RFC5890.
	Value string `json:"value"`
	// ResolvesTo specifies a list of references to one or more IP addresses or
	// domain names that the domain name resolves to. The objects referenced in
	// this list MUST be of type ipv4-addr or ipv6-addr or domain-name (for
	// cases such as CNAME records).
	ResolvesTo []Identifier `json:"resolves_to_refs,omitempty"`
}

func (o *DomainName) MarshalJSON() ([]byte, error) {
	return marshalToJSONHelper(o)
}

// AddResolvesTo describes that this Domain Name resolves to one or more IP
// addresses or domain names.
func (c *DomainName) AddResolvesTo(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForTypes(TypeDomainName, TypeIPv4Addr, TypeIPv6Addr) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeResolvesTo, c.ID, id, opts...)
}

// NewDomainName creates a new DomainName object.
func NewDomainName(value string, opts ...STIXOption) (*DomainName, error) {
	if value == "" {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeDomainName)
	obj := &DomainName{
		STIXCyberObservableObject: base,
		Value:                     value,
	}

	err := applyOptions(obj, opts)
	obj.ID = NewObservableIdentifier(fmt.Sprintf("[\"%s\"]", value), TypeDomainName)
	return obj, err
}
