// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import "fmt"

// Domain object represents the properties of a network domain name.
type Domain struct {
	*STIXCyberObservableObject
	// Value specifies the value of the domain name. The value of this property
	// MUST conform to RFC1034, and each domain and sub-domain contained within
	// the domain name MUST conform to RFC5890.
	Value string `json:"value"`
	// ResolvesTo specifies a list of references to one or more IP addresses or
	// domain names that the domain name resolves to. The objects referenced in
	// this list MUST be of type ipv4-addr or ipv6-addr or domain-name (for
	// cases such as CNAME records).
	//
	// DEPRECATED
	ResolvesTo []Identifier `json:"resolves_to_refs,omitempty"`
}

// AddResolvesTo describes that this Domain Name resolves to one or more IP
// addresses or domain names.
func (c *Domain) AddResolvesTo(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForTypes(TypeDomainName, TypeIPv4Addr, TypeIPv6Addr) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeResolvesTo, c.ID, id, opts...)
}

// NewDomain creates a new Domain object.
func NewDomain(value string, opts ...DomainOption) (*Domain, error) {
	if value == "" {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeDomainName)
	obj := &Domain{
		STIXCyberObservableObject: base,
		Value:                     value,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}
	obj.ID = NewObservableIdenfier(fmt.Sprintf("[\"%s\"]", value), TypeDomainName)
	return obj, nil
}

// DomainOption is an optional parameter when constructing a
// Domain object.
type DomainOption func(a *Domain)

/*
	Base object options
*/

// DomainOptionSpecVersion sets the STIX spec version.
func DomainOptionSpecVersion(ver string) DomainOption {
	return func(obj *Domain) {
		obj.SpecVersion = ver
	}
}

// DomainOptionObjectMarking sets the object marking attribute.
func DomainOptionObjectMarking(om []Identifier) DomainOption {
	return func(obj *Domain) {
		obj.ObjectMarking = om
	}
}

// DomainOptionGranularMarking sets the granular marking attribute.
func DomainOptionGranularMarking(gm *GranularMarking) DomainOption {
	return func(obj *Domain) {
		obj.GranularMarking = gm
	}
}

// DomainOptionDefanged sets the defanged attribute.
func DomainOptionDefanged(b bool) DomainOption {
	return func(obj *Domain) {
		obj.Defanged = b
	}
}

// DomainOptionExtension adds an extension.
func DomainOptionExtension(name string, value interface{}) DomainOption {
	return func(obj *Domain) {
		// Ignoring the error.
		obj.addExtension(name, value)
	}
}
